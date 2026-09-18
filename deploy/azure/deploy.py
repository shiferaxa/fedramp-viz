"""Deploy fedramp-viz to Azure App Service with Entra ID sign in.

Dry run by default: prints the plan and runs an ARM what-if, changes nothing.
--apply creates or reuses the Entra app registrations, deploys the Bicep,
pushes the code with an Oryx build and verifies the sign in redirect.

  python3 deploy.py --params my.params.json
  python3 deploy.py --params my.params.json --apply
  python3 deploy.py --params my.params.json --apply --code-only          # push code, skip Entra and ARM
  python3 deploy.py --params my.params.json --apply --onboard <tenant>   # (re)run the scanner grants for one tenant

Params file (JSON):
  {
    "subscription": "<hosting subscription id>",
    "location": "eastus2",
    "resourceGroupName": "fedramp-viz-rg",
    "appName": "fedramp-viz-app",
    "planName": "fedramp-viz-asp",
    "authAppName": "fedramp-viz-app",           # Entra app registration for sign in (hosting tenant)
    "scanSubscriptions": [],                    # optional: limit the scan to these subscription ids
    "scanAppName": "fedramp-viz-scanner",       # optional: multi tenant scanner app registration (hosting tenant)
    "scanTenants": ["<tenant id>", "..."],      # with scanAppName: tenants to scan
    "tags": {"service": "fedramp-viz"}
  }

Single tenant mode (no scanAppName): the web app's managed identity gets Reader on
the hosting subscription (Bicep) and on every other id in scanSubscriptions.

Multi tenant mode (scanAppName + scanTenants): a multi tenant app registration is
created in the hosting tenant with a federated identity credential that trusts the
web app's managed identity, so there is no secret. In each scanned tenant its
service principal is created (that is the admin consent) and given Reader on every
enabled subscription the operator can see there. Onboarding a tenant needs an
account that can create service principals and role assignments in that tenant;
sign in as one and rerun --onboard <tenant> for the ones that failed.

Every az call is an argv list, never a shell string. The sign in client secret
exists only in memory and in a 0600 temp parameters file deleted when the run ends.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PLACEHOLDER_CLIENT_ID = "00000000-0000-0000-0000-000000000000"
SHIP = ["pyproject.toml", "requirements.txt", "README.md", "LICENSE"]
FIC_NAME = "web-app-managed-identity"
EXCHANGE_AUDIENCE = "api://AzureADTokenExchange"


def az(*args: str, check: bool = True) -> str:
    p = subprocess.run(["az", *args], capture_output=True, text=True)
    if p.returncode != 0 and check:
        sys.exit(f"az {' '.join(args[:4])} failed:\n{p.stderr.strip()}")
    return p.stdout


def azj(*args: str):
    out = az(*args, "-o", "json")
    return json.loads(out) if out.strip() else None


def azj_opt(*args: str):
    """Like azj but None when the command fails (not found, no access)."""
    p = subprocess.run(["az", *args, "-o", "json"], capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else None


def temp_json(body: dict) -> str:
    fd, path = tempfile.mkstemp(prefix="fedramp-viz-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(body, f)
    os.chmod(path, 0o600)
    return path


# ---- Entra ----------------------------------------------------------------

def app_registration(params: dict, apply: bool) -> tuple[str, str]:
    """Sign in app (single tenant, hosting tenant). Returns (client id, client secret)."""
    name = params["authAppName"]
    redirect = f"https://{params['appName']}.azurewebsites.net/.auth/login/aad/callback"
    found = azj("ad", "app", "list", "--display-name", name, "--query", "[].{appId:appId,uris:web.redirectUris}")
    if found:
        client_id = found[0]["appId"]
        print(f"sign in app {name!r} exists: {client_id}, redirect uris {found[0]['uris']}")
    else:
        print(f"sign in app {name!r} absent; {'creating' if apply else 'would create'} with redirect {redirect}")
        if not apply:
            return PLACEHOLDER_CLIENT_ID, "dry-run"
        created = azj("ad", "app", "create", "--display-name", name, "--sign-in-audience", "AzureADMyOrg",
                      "--web-redirect-uris", redirect, "--enable-id-token-issuance", "true")
        client_id = created["appId"]
        print(f"created sign in app {client_id}")
    if not apply:
        return client_id, "dry-run"
    cred = azj("ad", "app", "credential", "reset", "--id", client_id, "--display-name", "app-service-auth", "--years", "2", "--append")
    print("minted a new client secret (2 years, older secrets kept; prune them in Entra when convenient)")
    return client_id, cred["password"]


def scanner_app(params: dict, apply: bool) -> str:
    """Multi tenant scanner app in the hosting tenant, with its service principal. Returns the client id."""
    name = params["scanAppName"]
    found = azj("ad", "app", "list", "--display-name", name, "--query", "[].{appId:appId,audience:signInAudience}")
    if found:
        client_id = found[0]["appId"]
        print(f"scanner app {name!r} exists: {client_id} ({found[0]['audience']})")
    else:
        print(f"scanner app {name!r} absent; {'creating' if apply else 'would create'} (multi tenant, no secret)")
        if not apply:
            return PLACEHOLDER_CLIENT_ID
        client_id = azj("ad", "app", "create", "--display-name", name, "--sign-in-audience", "AzureADMultipleOrgs")["appId"]
        print(f"created scanner app {client_id}")
    if azj_opt("ad", "sp", "show", "--id", client_id) is None:
        print(f"{'creating' if apply else 'would create'} the scanner service principal in the hosting tenant")
        if apply:
            az("ad", "sp", "create", "--id", client_id)
    return client_id


def federate(client_id: str, principal_id: str, hosting_tenant: str, apply: bool) -> None:
    """Federated identity credential on the scanner app that trusts the web app's managed identity."""
    existing = azj_opt("ad", "app", "federated-credential", "list", "--id", client_id) or []
    if any(f.get("name") == FIC_NAME for f in existing):
        print(f"federated credential {FIC_NAME!r} already on the scanner app")
        return
    print(f"{'adding' if apply else 'would add'} federated credential: issuer tenant {hosting_tenant}, subject {principal_id}")
    if not apply:
        return
    path = temp_json({"name": FIC_NAME, "issuer": f"https://login.microsoftonline.com/{hosting_tenant}/v2.0",
                      "subject": principal_id, "audiences": [EXCHANGE_AUDIENCE],
                      "description": "fedramp-viz web app managed identity"})
    try:
        az("ad", "app", "federated-credential", "create", "--id", client_id, "--parameters", f"@{path}")
    finally:
        os.unlink(path)
    print("federated credential added")


def onboard_tenant(tenant: str, client_id: str, apply: bool) -> None:
    """Create the scanner's service principal in `tenant` and grant Reader on every enabled subscription visible there."""
    subs = [a for a in azj("account", "list") if a["tenantId"] == tenant and a["state"] == "Enabled"]
    print(f"\n== tenant {tenant}: {len(subs)} enabled subscription(s) visible")
    if not subs:
        print("   nothing to do (sign in to that tenant first: az login --tenant <id>)")
        return
    az("account", "set", "--subscription", subs[0]["id"])
    sp = azj_opt("ad", "sp", "show", "--id", client_id)
    if sp is None:
        print(f"   service principal absent; {'creating' if apply else 'would create'} (this is the admin consent)")
        if not apply:
            return
        p = subprocess.run(["az", "ad", "sp", "create", "--id", client_id, "-o", "json"], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"   FAILED to create the service principal: {p.stderr.strip()[-400:]}")
            return
        sp = json.loads(p.stdout)
    object_id = sp["id"]
    for s in subs:
        scope = f"/subscriptions/{s['id']}"
        have = azj_opt("role", "assignment", "list", "--scope", scope, "--subscription", s["id"],
                       "--query", f"[?principalId=='{object_id}' && roleDefinitionName=='Reader'].id")
        if have:
            print(f"   Reader ok      {s['name']} ({s['id']})")
            continue
        if not apply:
            print(f"   would grant    {s['name']} ({s['id']})")
            continue
        p = subprocess.run(["az", "role", "assignment", "create", "--assignee-object-id", object_id, "--assignee-principal-type", "ServicePrincipal",
                            "--role", "Reader", "--scope", scope, "--subscription", s["id"], "-o", "none"], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"   FAILED         {s['name']} ({s['id']}): {p.stderr.strip()[-300:]}")
        else:
            print(f"   Reader granted {s['name']} ({s['id']})")


def grant_reader(params: dict, principal_id: str, apply: bool) -> None:
    """Single tenant mode: Reader for the managed identity on the other scanSubscriptions."""
    for sub in params.get("scanSubscriptions", []):
        if sub == params["subscription"]:
            continue
        scope = f"/subscriptions/{sub}"
        have = azj("role", "assignment", "list", "--scope", scope, "--role", "Reader", "--subscription", sub,
                   "--query", f"[?principalId=='{principal_id}'].id")
        if have:
            print(f"Reader already on {sub}")
            continue
        print(f"{'granting' if apply else 'would grant'} Reader on {sub}")
        if apply:
            az("role", "assignment", "create", "--assignee-object-id", principal_id, "--assignee-principal-type", "ServicePrincipal",
               "--role", "Reader", "--scope", scope, "--subscription", sub)


# ---- ARM ------------------------------------------------------------------

def arm(params: dict, client_id: str, secret: str, scan_client_id: str, apply: bool) -> dict | None:
    multi = bool(params.get("scanAppName"))
    body = {
        "$schema": "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "resourceGroupName": {"value": params["resourceGroupName"]},
            "location": {"value": params["location"]},
            "appName": {"value": params["appName"]},
            "planName": {"value": params["planName"]},
            "authClientId": {"value": client_id},
            "authClientSecret": {"value": secret},
            "scanSubscriptions": {"value": ",".join(params.get("scanSubscriptions", []))},
            "scanTenants": {"value": ",".join(params.get("scanTenants", [])) if multi else ""},
            "scanClientId": {"value": scan_client_id if multi else ""},
            "grantReader": {"value": not multi},
            "tags": {"value": params.get("tags", {"service": "fedramp-viz"})},
        },
    }
    path = temp_json(body)
    try:
        common = ["--location", params["location"], "--template-file", str(HERE / "main.bicep"), "--parameters", f"@{path}",
                  "--name", f"fedramp-viz-{uuid.uuid4().hex[:8]}"]
        print("\nARM what-if:")
        print(az("deployment", "sub", "what-if", *common))
        if not apply:
            return None
        out = azj("deployment", "sub", "create", *common, "--query", "properties.outputs")
        print(f"deployed: hostname {out['hostname']['value']}, identity {out['principalId']['value']}")
        return {k: v["value"] for k, v in out.items()}
    finally:
        os.unlink(path)


# ---- code -----------------------------------------------------------------

def build_zip() -> Path:
    files = subprocess.run(["git", "ls-files", "fedramp_viz", *SHIP], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    path = Path(tempfile.gettempdir()) / "fedramp-viz-deploy.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in files:
            z.write(ROOT / rel, rel)
    print(f"zip {path}: {len(files)} files, {path.stat().st_size // 1024} KB")
    return path


def push_code(params: dict, apply: bool) -> None:
    z = build_zip()
    if not apply:
        print("would run: az webapp deploy --type zip (Oryx build from requirements.txt)")
        return
    p = subprocess.run(["az", "webapp", "deploy", "--resource-group", params["resourceGroupName"], "--name", params["appName"],
                        "--src-path", str(z), "--type", "zip", "--clean", "true"], capture_output=True, text=True)
    if p.returncode != 0:
        # The CLI can report failure while the Kudu build already finished (seen once, cause unknown);
        # show the deployment log so the operator can tell a real build failure from that.
        print(f"az webapp deploy exited {p.returncode}: {p.stderr.strip()[-800:]}")
        print("latest deployment log tail:")
        print(az("webapp", "log", "deployment", "show", "--resource-group", params["resourceGroupName"], "--name", params["appName"], "-o", "tsv", check=False)[-1500:])
        sys.exit(1)
    print("code deployed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def verify(params: dict) -> None:
    host = f"https://{params['appName']}.azurewebsites.net"
    state = az("webapp", "show", "--resource-group", params["resourceGroupName"], "--name", params["appName"], "--query", "state", "-o", "tsv").strip()
    print(f"app state: {state}")
    for path in ("/", "/api/meta"):
        req = urllib.request.Request(host + path, headers={"User-Agent": "fedramp-viz-deploy"})
        try:
            urllib.request.build_opener(NoRedirect()).open(req, timeout=30)
            print(f"{path}: 200 WITHOUT sign in, authentication is not enforced, investigate")
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "")
            ok = e.code in (302, 401) and ("login.microsoftonline.com" in loc or e.code == 401)
            print(f"{path}: {e.code} {'-> Entra sign in' if ok else loc[:120]}")


# ---- main -----------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--params", required=True)
    ap.add_argument("--apply", action="store_true", help="make changes (default is a dry run with what-if)")
    ap.add_argument("--code-only", action="store_true", help="skip Entra and ARM, only push the code")
    ap.add_argument("--onboard", metavar="TENANT", help="only (re)run the scanner service principal and Reader grants for this tenant")
    args = ap.parse_args()
    params = json.loads(Path(args.params).read_text(encoding="utf-8"))
    for k in ("subscription", "location", "resourceGroupName", "appName", "planName", "authAppName"):
        if k not in params:
            sys.exit(f"params file is missing {k!r}")
    multi = bool(params.get("scanAppName"))
    if multi and not params.get("scanTenants"):
        sys.exit("scanAppName needs scanTenants")

    original = azj("account", "show")["id"]
    print(f"{'APPLY' if args.apply else 'DRY RUN'}: {params['appName']} in {params['resourceGroupName']} ({params['location']}), sub {params['subscription']}")
    print(f"scan mode: {'multi tenant, ' + str(len(params['scanTenants'])) + ' tenant(s)' if multi else 'single tenant (managed identity)'}")
    try:
        az("account", "set", "--subscription", params["subscription"])
        hosting_tenant = azj("account", "show")["tenantId"]

        if args.onboard:
            client_id = scanner_app(params, apply=False)
            if client_id == PLACEHOLDER_CLIENT_ID:
                sys.exit("scanner app does not exist yet; run a full --apply first")
            onboard_tenant(args.onboard, client_id, args.apply)
            return 0

        if not args.code_only:
            auth_client_id, secret = app_registration(params, args.apply)
            scan_client_id = scanner_app(params, args.apply) if multi else ""
            outputs = arm(params, auth_client_id, secret, scan_client_id, args.apply)
            if multi:
                if outputs:
                    federate(scan_client_id, outputs["principalId"], hosting_tenant, args.apply)
                    for tenant in params["scanTenants"]:
                        onboard_tenant(tenant, scan_client_id, args.apply)
                        az("account", "set", "--subscription", params["subscription"])
                else:
                    print("federated credential and per tenant Reader grants are evaluated after the app identity exists (apply)")
            elif outputs:
                grant_reader(params, outputs["principalId"], args.apply)
        push_code(params, args.apply)
        if args.apply:
            verify(params)
    finally:
        subprocess.run(["az", "account", "set", "--subscription", original], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
