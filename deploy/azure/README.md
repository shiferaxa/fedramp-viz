# Deploy to Azure App Service

One Linux web app (B1) running the live scan, with Entra ID sign in enforced by App Service authentication on every route including the API. No database, no storage. The only secret is the sign in client secret; scanning never uses one.

```
python3 deploy.py --params my.params.json                    # dry run: plan plus ARM what-if, changes nothing
python3 deploy.py --params my.params.json --apply            # app registrations, deploy, grants, push code, verify
python3 deploy.py --params my.params.json --apply --code-only            # later code updates
python3 deploy.py --params my.params.json --apply --onboard <tenant id>  # redo the grants for one tenant
```

## Two scan modes

**Single tenant** (no `scanAppName`): the web app's managed identity reads Resource Graph in the hosting tenant. Bicep grants it Reader on the hosting subscription; `scanSubscriptions` adds others in the same tenant.

**Several tenants** (`scanAppName` + `scanTenants`): a multi tenant app registration in the hosting tenant carries a federated identity credential that trusts the web app's managed identity (issuer = hosting tenant, subject = the identity's principal id, audience `api://AzureADTokenExchange`). At run time the app exchanges its managed identity token for a scanner token per tenant and runs one Resource Graph query per tenant. In each scanned tenant the scanner needs its service principal (creating it is the admin consent, no API permissions involved) and Reader on the subscriptions. `deploy.py` does that for every enabled subscription the operator can see in the tenant; a tenant where the operator lacks the rights is reported, not fatal. Sign in there as an account that can create service principals and role assignments, then rerun `--onboard <tenant id>`.

## What `--apply` does, in order

1. Sign in app registration named `authAppName` in the hosting tenant (single tenant, ID token issuance, redirect `https://<appName>.azurewebsites.net/.auth/login/aad/callback`). Reused if it exists. A new client secret (2 years) is minted each apply with `--append`; prune old ones in Entra when convenient. Guests of the hosting tenant can sign in too.
2. Scanner app registration named `scanAppName` (multi tenant mode only) plus its service principal in the hosting tenant.
3. `main.bicep` at subscription scope: resource group, B1 Linux plan, web app with a system assigned identity, `httpsOnly`, TLS 1.2 on the site and SCM endpoints, FTPS off, always on, App Service authentication (`authsettingsV2`, redirect unauthenticated requests to Entra, hosting tenant issuer), app settings `FEDRAMP_VIZ_TENANTS` and `FEDRAMP_VIZ_SCAN_CLIENT_ID` in multi tenant mode, and Reader for the identity on the hosting subscription in single tenant mode.
4. Federated credential on the scanner app, then per tenant onboarding (service principal + Reader per subscription). Single tenant mode grants Reader for the managed identity on the other `scanSubscriptions` instead.
5. Zip of `fedramp_viz/`, `pyproject.toml`, `requirements.txt`, `README.md`, `LICENSE` pushed with `az webapp deploy`; Oryx installs `.[azure]` from `requirements.txt`. Startup command: `python -m fedramp_viz.cli serve --source azure --host 0.0.0.0 --port 8000`.
6. Verification: the app is `Running` and `/` and `/api/meta` answer 302 or 401 for an anonymous client (browsers get the redirect to `login.microsoftonline.com`, other clients 401).

## Notes

* The scan runs at process start, so the first request after a deploy or restart waits a few seconds per tenant. Rescan re-reads Resource Graph. The startup log line `scanned N resources across M subscription(s)` is the quickest health check (`az webapp log download`, StartupLogs).
* Resource Graph returns nothing for subscriptions the identity cannot read, so a missing grant shows up as a low count for that tenant, not an error.
* Access control is "any user or guest of the hosting tenant can sign in" by default. To limit it, set the sign in app's enterprise application to Assignment required and assign the users or a group.
* `az webapp auth show` prints nulls for a v2 configuration; read `.../config/authsettingsV2` with `az rest` instead.
* Rollback: rerun `--code-only` from the previous commit. Removing everything is `az group delete` plus deleting the two app registrations and the scanner's service principals in the scanned tenants (their Reader assignments go with them).
