"""Deploy fedramp-viz to Azure App Service with Entra ID sign in.

Dry run by default: prints the plan and runs an ARM what-if, changes nothing.
--apply creates or reuses the Entra app registration, deploys the Bicep,
pushes the code with an Oryx build and verifies the sign in redirect.

  python3 deploy.py --params my.params.json
  python3 deploy.py --params my.params.json --apply
  python3 deploy.py --params my.params.json --apply --code-only   # push code, skip ARM and Entra

Params file (JSON):
  {
    "subscription": "<deployment subscription id>",
    "location": "eastus2",
    "resourceGroupName": "fedramp-viz-rg",
    "appName": "fedramp-viz-app",
    "planName": "fedramp-viz-asp",
    "authAppName": "fedramp-viz-app",           # Entra app registration display name
    "scanSubscriptions": ["<sub id>", "..."],   # what the live scan covers; Reader is granted on each
    "tags": {"service": "fedramp-viz"}
  }

Needs: az CLI signed in with rights to create the resource group, role
assignments on the scanned subscriptions and an app registration in the tenant.
Every az call is an argv list, never a shell string, so ids and secrets are
never re-parsed. The client secret exists only in memory and in a 0600 temp
parameters file that is deleted when the run ends.
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


def az(*args: str, check: bool = True) -> str:
    p = subprocess.run(["az", *args], capture_output=True, text=True)
    if p.returncode != 0 and check:
        sys.exit(f"az {' '.join(args[:4])} failed:\n{p.stderr.strip()}")
    return p.stdout


def azj(*args: str):
    out = az(*args, "-o", "json")
    return json.loads(out) if out.strip() else None


def app_registration(params: dict, apply: bool) -> tuple[str, str]:
    """Return (client id, client secret). Creates the registration on --apply."""
    name = params["authAppName"]
    redirect = f"https://{params['appName']}.azurewebsites.net/.auth/login/aad/callback"
    found = azj("ad", "app", "list", "--display-name", name, "--query", "[].{appId:appId,uris:web.redirectUris}")
    if found:
        client_id = found[0]["appId"]
        print(f"app registration {name!r} exists: {client_id}, redirect uris {found[0]['uris']}")
    else:
        print(f"app registration {name!r} absent; {'creating' if apply else 'would create'} with redirect {redirect}")
        if not apply:
            return PLACEHOLDER_CLIENT_ID, "dry-run"
        created = azj("ad", "app", "create", "--display-name", name, "--sign-in-audience", "AzureADMyOrg",
                      "--web-redirect-uris", redirect, "--enable-id-token-issuance", "true")
        client_id = created["appId"]
        print(f"created app registration {client_id}")
    if not apply:
        return client_id, "dry-run"
    cred = azj("ad", "app", "credential", "reset", "--id", client_id, "--display-name", "app-service-auth", "--years", "2", "--append")
    print("minted a new client secret (2 years, older secrets kept; prune them in Entra when convenient)")
    return client_id, cred["password"]


def arm(params: dict, client_id: str, secret: str, apply: bool) -> dict | None:
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
            "scanSubscriptions": {"value": ",".join(params["scanSubscriptions"])},
            "tags": {"value": params.get("tags", {"service": "fedramp-viz"})},
        },
    }
    fd, path = tempfile.mkstemp(prefix="fedramp-viz-params-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(body, f)
        os.chmod(path, 0o600)
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


def grant_reader(params: dict, principal_id: str, apply: bool) -> None:
    """Reader on every scanned subscription other than the deployment one (Bicep covers that one)."""
    for sub in params["scanSubscriptions"]:
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
    az("webapp", "deploy", "--resource-group", params["resourceGroupName"], "--name", params["appName"], "--src-path", str(z), "--type", "zip", "--clean", "true")
    print("code deployed")


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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--params", required=True)
    ap.add_argument("--apply", action="store_true", help="make changes (default is a dry run with what-if)")
    ap.add_argument("--code-only", action="store_true", help="skip Entra and ARM, only push the code")
    args = ap.parse_args()
    params = json.loads(Path(args.params).read_text(encoding="utf-8"))
    for k in ("subscription", "location", "resourceGroupName", "appName", "planName", "authAppName", "scanSubscriptions"):
        if k not in params:
            sys.exit(f"params file is missing {k!r}")

    original = azj("account", "show")["id"]
    print(f"{'APPLY' if args.apply else 'DRY RUN'}: {params['appName']} in {params['resourceGroupName']} ({params['location']}), sub {params['subscription']}")
    print(f"scan covers {len(params['scanSubscriptions'])} subscription(s)")
    try:
        az("account", "set", "--subscription", params["subscription"])
        if not args.code_only:
            client_id, secret = app_registration(params, args.apply)
            outputs = arm(params, client_id, secret, args.apply)
            if outputs:
                grant_reader(params, outputs["principalId"], args.apply)
            elif not args.apply:
                print("Reader grants on the other scanned subscriptions are evaluated after the app identity exists (apply)")
        push_code(params, args.apply)
        if args.apply:
            verify(params)
    finally:
        subprocess.run(["az", "account", "set", "--subscription", original], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
