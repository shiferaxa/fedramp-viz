# Security

This tool reads a description of your infrastructure, which is sensitive on its own. Here is what it does and does not do, so you can decide how to run it.

## What the tool touches

* Cloud access is read only. The live Azure provider runs one Resource Graph query. Reader on the subscriptions is enough. There is no code path that writes to a cloud API.
* No telemetry, no update checks, no calls to anything other than your cloud API (and only in live mode). The dashboard loads no external scripts, styles or fonts, so it works air gapped.
* Nothing is persisted. Inventory and results live in process memory. `--json` writes a report only where you tell it to.
* Credentials are never read from the request or stored. Live mode uses `DefaultAzureCredential`, so use a managed identity or workload identity when hosting and a service principal secret only as a last resort.

## Hosting

Defaults are the safe ones:

* the server binds to 127.0.0.1 unless you pass `--host`
* `FEDRAMP_VIZ_TOKEN` makes every `/api` route require `Authorization: Bearer <token>`; the HTML shell stays public but carries no data
* responses carry `Content-Security-Policy: default-src 'self'` (no inline scripts or styles), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`
* interactive API docs are disabled
* the Docker image runs as an unprivileged user; the compose file drops all capabilities, sets no-new-privileges and a read only root filesystem

The token is a shared secret meant for small teams. For anything wider, put the service behind a reverse proxy that terminates TLS and does your real authentication (OIDC, mTLS, your SSO), and keep the token as defense in depth.

## Handling exports

An exported inventory contains resource ids, names, tags and full property bags. Treat the file like a network diagram: keep it off shared drives, delete it when the review is done, and do not commit it. `exports/` is in `.gitignore` for that reason.

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue. Include the version, how to reproduce, and what an attacker gains. You will get a response within seven days.
