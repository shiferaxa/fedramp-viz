# fedramp-viz

Self hosted, read only scanner that checks cloud infrastructure against the FedRAMP Low, Moderate and High baselines and shows the result as a dashboard. Azure is supported today; the provider layer is built so GCP and AWS can be added without touching the engine or the UI.

It answers three questions for a given impact level:

1. Which resource settings fail a technical check that maps to a FedRAMP control?
2. Which NIST SP 800-53 Rev 5 controls in that baseline have automated evidence, and which are still on a person?
3. What changes when you move from Moderate to High?

It is not an authorization. Most FedRAMP controls are policy, process and people. The dashboard says out loud how much of the baseline an inventory scan can actually see (around 8 to 10 percent of controls), so the score is a posture score for the technical settings, not a readiness score for an ATO.

## How it works

```
cloud (Azure Resource Graph)  or  exported JSON
            |
   providers/   normalize into Resource objects (id, type, location, properties)
            |
   rules/azure/ 55 checks, each mapped to control ids like SC-7(5)
            |
   baselines   FedRAMP Rev 5 Low (156) / Moderate (323) / High (410) control sets
            |
   engine.py   run the checks that apply at the chosen level, roll up by
               control, family, resource and resource group, score it
            |
   api.py + web/   FastAPI JSON API and a dependency free dashboard
   cli.py          same engine from the terminal, JSON report for CI
```

A rule declares the controls it gives evidence for and the lowest impact level where it is enforced. The engine keeps a rule only if at least one of its controls is in the selected baseline, and reports it as deferred when the level is below the rule's minimum. That is how the same inventory produces a different picture at Low, Moderate and High.

## Quick start

```
python -m venv .venv
.venv\Scripts\activate           # or source .venv/bin/activate
pip install -e ".[dev]"
fedramp-viz assess --source samples/azure-sample.json --level high
fedramp-viz serve  --source samples/azure-sample.json
```

Open http://127.0.0.1:8080/. The sample is a synthetic company footprint with deliberate problems in it.

### Scan your own Azure tenant

Option A, export first (nothing but the Azure CLI touches your tenant):

```
az login
az graph query -q "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags, properties, sku, kind, identity" --first 1000 -o json > exports/azure.json
fedramp-viz serve --source exports/azure.json
```

Resource Graph returns at most 1000 rows per call. For larger tenants run it once per subscription with `--subscriptions <id>` or page with `--skip-token`, and concatenate the `data` arrays.

Option B, live query:

```
pip install -e ".[azure]"
fedramp-viz serve --source azure --subscription <id>
```

Credentials come from `DefaultAzureCredential` (az login, environment variables, managed identity or workload identity). The identity needs only the Reader role. The tool never writes to Azure.

### Host it for a team

```
docker compose up --build
```

The compose file drops all capabilities, runs read only with a non root user, mounts `./exports` read only and binds to loopback. Put a TLS reverse proxy with your own authentication in front of it and set `FEDRAMP_VIZ_TOKEN` so every API call needs a bearer token. See [SECURITY.md](SECURITY.md) for the full posture.

On Azure, [deploy/azure/](deploy/azure/README.md) stands up one App Service web app that scans live under its own managed identity (Reader only) with Entra ID sign in in front of every route. `python3 deploy/azure/deploy.py --params ...` is a dry run with an ARM what-if; add `--apply` to deploy.

### CI gate

```
fedramp-viz assess --source exports/azure.json --level moderate --json report.json --fail-on-findings
```

## What is checked

`fedramp-viz rules` lists every rule with its severity, minimum level and controls. Coverage today, all for Azure:

| Area | Examples |
|---|---|
| Boundary | region inside the FedRAMP authorization boundary, service on Microsoft's in scope list |
| Network | NSG rules exposing SSH, RDP, WinRM or all ports to the internet, subnets without an NSG, DDoS protection (High), NICs with public IPs |
| Storage | HTTPS only, TLS 1.2, anonymous blob access, network restriction, shared key auth, customer managed keys and double encryption (High) |
| Compute | managed disks, encryption at host, SSH key only Linux, Trusted Launch, disk CMK and export policy |
| Key Vault | soft delete, purge protection, RBAC, network restriction, Premium HSM (High) |
| Databases | SQL, PostgreSQL, Cosmos DB and Redis: TLS, public access, Entra only auth, CMK, backup redundancy |
| AKS | Entra ID with Azure RBAC, local accounts, private API server, network policy, monitoring, Defender, Policy add-on, KMS |
| Platform | App Service (sites and deployment slots) HTTPS, TLS and identity, Container Registry admin user and public access, Log Analytics retention and private access |

Checks that need data outside the resource inventory (diagnostic settings, Defender plans, activity log alerts, RBAC assignments) are not in this version. They need extra Resource Graph tables and are the next thing to add.

### Statuses

* pass and fail count toward the score, weighted high 3, medium 2, low 1
* manual means the inventory cannot decide (a public web app that may sit behind a WAF, an unknown service, a Resource Graph row that ships a setting as null); a person closes it
* deferred means the rule only applies at a higher level; the Manual tile shows how many
* not assessed on the Controls tab means no rule maps to that control

## Baselines

`fedramp_viz/data/controls.json` is generated, do not edit it. It combines the NIST SP 800-53 Rev 5 OSCAL catalog with the FedRAMP Rev 5 OSCAL baseline profiles kept in `baselines/`. Regenerate with `python scripts/build_catalog.py`. To try a different baseline, for example the LI-SaaS profile, pass `--oscal-profile low=path/to/profile.json`.

## Adding a rule

Add a decorated function to the right module under `fedramp_viz/rules/azure/`:

```python
@rule("AZ-KV-006", "Key Vault has a private endpoint", controls=["SC-7"], resource_types=["microsoft.keyvault/vaults"],
      severity=Severity.MEDIUM, min_level=ImpactLevel.HIGH, remediation="az network private-endpoint create ...")
def private_endpoint(res: Resource):
    """One sentence on why the control cares."""
    ...
    return passed("...") or failed("...", evidence=value)
```

The docstring is the description shown in the UI. `tests/test_rules.py` checks that every control id exists in the catalog and every rule has a remediation. Run `pytest`.

## Adding a provider

Implement `Provider.resources()` returning `Resource` objects with `provider="gcp"` or `"aws"`, register it in `providers/__init__.py`, and add a `rules/<provider>/` package. Rules carry a `provider` field so the engine only runs them against matching resources. The baseline, engine, API and dashboard need no changes.

## Roadmap

* diagnostic settings, Defender for Cloud plans and RBAC via extra Resource Graph tables
* GCP (Cloud Asset Inventory) and AWS (Config or Resource Explorer) providers
* OSCAL assessment results export so findings can feed an SSP toolchain
* accepted risk file so known findings can be waived with a reason and expiry

## License

MIT. See [LICENSE](LICENSE).
