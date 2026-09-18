"""Log Analytics workspace checks (audit retention and exposure)."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, manual, passed
from .. import rule

T = ["microsoft.operationalinsights/workspaces"]

MIN_ONLINE_DAYS = 90
FEDRAMP_RETENTION_DAYS = 365


@rule("AZ-LAW-001", "Log Analytics retention meets FedRAMP audit retention", controls=["AU-11", "AU-4"], resource_types=T, severity=Severity.MEDIUM,
      remediation=f"az monitor log-analytics workspace update -g <rg> -n <name> --retention-time {FEDRAMP_RETENTION_DAYS}, or keep at least {MIN_ONLINE_DAYS} days interactive with archive or export covering one year.")
def retention(res: Resource):
    """FedRAMP expects audit records kept for at least a year, with 90 days readily available. Interactive retention below 90 days fails; between 90 days and a year needs archive or export to be confirmed."""
    days = res.prop("retentionInDays")
    if not isinstance(days, (int, float)):
        return manual("Retention not present in export", retentionInDays=days)
    if days < MIN_ONLINE_DAYS:
        return failed(f"Retention is {int(days)} days, below the {MIN_ONLINE_DAYS} day online minimum", retentionInDays=days)
    if days < FEDRAMP_RETENTION_DAYS and res.extra.get("_level") != "low":
        return manual(f"Retention is {int(days)} days; confirm archive tier or export keeps records for one year", retentionInDays=days)
    return passed(f"Retention is {int(days)} days", retentionInDays=days)


@rule("AZ-LAW-002", "Log Analytics workspace is not reachable over the public network", controls=["SC-7", "AU-9"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.HIGH,
      remediation="Create an Azure Monitor Private Link Scope, link the workspace and set public ingestion and query to Disabled.")
def private_access(res: Resource):
    """Audit logs are evidence; both ingestion and query should stay inside the boundary."""
    ing = res.prop("publicNetworkAccessForIngestion")
    qry = res.prop("publicNetworkAccessForQuery")
    ok = all(isinstance(v, str) and v.lower() == "disabled" for v in (ing, qry))
    if ok:
        return passed("Public ingestion and query disabled")
    return failed("Public ingestion or query still enabled", publicNetworkAccessForIngestion=ing, publicNetworkAccessForQuery=qry)
