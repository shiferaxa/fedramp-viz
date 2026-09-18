# Deploy to Azure App Service

One Linux web app (B1) running the live Azure scan under its own managed identity, with Entra ID sign in enforced by App Service authentication on every route including the API. Nothing else: no database, no storage, no secrets beyond the sign in client secret.

```
python3 deploy.py --params my.params.json          # dry run: plan plus ARM what-if, changes nothing
python3 deploy.py --params my.params.json --apply  # create or reuse the app registration, deploy, push code, verify
python3 deploy.py --params my.params.json --apply --code-only   # later code updates
```

## What `--apply` does, in order

1. Entra app registration named `authAppName` (single tenant, ID token issuance, redirect `https://<appName>.azurewebsites.net/.auth/login/aad/callback`). Reused if it exists. A new client secret (2 years) is minted each apply with `--append`; prune old ones in Entra when convenient.
2. `main.bicep` at subscription scope: resource group, B1 Linux plan, web app with a system assigned identity, `httpsOnly`, TLS 1.2 on the site and SCM endpoints, FTPS off, always on, App Service authentication (`authsettingsV2`, redirect unauthenticated requests to Entra, this tenant only), and Reader for the identity on the deployment subscription.
3. Reader on every other subscription in `scanSubscriptions`.
4. Zip of `fedramp_viz/`, `pyproject.toml`, `requirements.txt`, `README.md`, `LICENSE` pushed with `az webapp deploy`; Oryx installs `.[azure]` from `requirements.txt`. The startup command is `python -m fedramp_viz.cli serve --source azure --host 0.0.0.0 --port 8000 --subscription ...`.
5. Verification: the app is `Running` and both `/` and `/api/meta` answer 302 to `login.microsoftonline.com` for an anonymous client.

## Notes

* The scan runs at process start against the managed identity, so the first request after a deploy or restart waits a few seconds. Rescan re-reads Resource Graph.
* The identity only ever needs Reader. Resource Graph returns nothing for subscriptions it cannot read, so a missing grant shows up as a low resource count, not an error.
* Cross tenant is out of scope: a managed identity reads its own tenant only. Deploy one instance per tenant you need to scan.
* Access control is "any user in the tenant can sign in" by default. To limit it, set the app registration to require user assignment (Enterprise application, Properties, Assignment required) and assign the users or a group.
* Rollback: the web app keeps the previous deployment; `az webapp deployment list-publishing-credentials` is not needed, just re run `--code-only` from the previous commit. Removing everything is `az group delete` plus deleting the app registration.
