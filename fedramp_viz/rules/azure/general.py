"""Checks that apply to every Azure resource: where it runs and whether the service is in scope."""

from __future__ import annotations

from ...models import Resource, Severity, failed, manual, not_applicable, passed
from .. import rule

# Regions inside Microsoft's FedRAMP authorization boundaries. Azure public
# (commercial) US regions are covered by the Azure FedRAMP High P-ATO;
# Azure Government regions carry their own FedRAMP High authorization.
# Override with FEDRAMP_VIZ_REGIONS (comma separated) if your boundary differs.
COMMERCIAL_US_REGIONS = {
    "eastus", "eastus2", "centralus", "northcentralus", "southcentralus",
    "westcentralus", "westus", "westus2", "westus3",
}
GOVERNMENT_REGIONS = {"usgovvirginia", "usgovtexas", "usgovarizona", "usdodcentral", "usdodeast"}
ALLOWED_REGIONS = COMMERCIAL_US_REGIONS | GOVERNMENT_REGIONS
GLOBAL_REGIONS = {"global", ""}

# Region-less control plane objects that hold no customer data: alert rules,
# action groups and Traffic Manager profiles. They are always "global", so asking
# a person to confirm where their data lives is noise. Reported not applicable instead.
NO_DATA_GLOBAL_TYPES = {
    "microsoft.alertsmanagement/smartdetectoralertrules",
    "microsoft.insights/metricalerts",
    "microsoft.insights/actiongroups",
    "microsoft.insights/activitylogalerts",
    "microsoft.network/trafficmanagerprofiles",
}

# Resource providers whose services are listed in Microsoft's "Azure services in
# FedRAMP scope" table. Anything not listed here is reported as manual so a
# person confirms it against the current Microsoft list; it is not a failure.
IN_SCOPE_PROVIDERS = {
    "microsoft.compute", "microsoft.network", "microsoft.storage", "microsoft.keyvault",
    "microsoft.sql", "microsoft.web", "microsoft.containerservice", "microsoft.containerregistry",
    "microsoft.documentdb", "microsoft.operationalinsights", "microsoft.insights",
    "microsoft.dbforpostgresql", "microsoft.dbformysql", "microsoft.cache", "microsoft.servicebus",
    "microsoft.eventhub", "microsoft.apimanagement", "microsoft.logic", "microsoft.automation",
    "microsoft.recoveryservices", "microsoft.managedidentity", "microsoft.authorization",
    "microsoft.resources", "microsoft.security", "microsoft.operationsmanagement",
    "microsoft.eventgrid", "microsoft.datafactory", "microsoft.databricks", "microsoft.cdn",
    "microsoft.app", "microsoft.cognitiveservices", "microsoft.machinelearningservices",
    "microsoft.devices", "microsoft.signalrservice", "microsoft.search", "microsoft.batch",
    "microsoft.hdinsight", "microsoft.synapse", "microsoft.streamanalytics", "microsoft.relay",
    "microsoft.notificationhubs", "microsoft.netapp", "microsoft.datalakestore", "microsoft.dbformariadb",
    "microsoft.alertsmanagement", "microsoft.portal", "microsoft.compute/galleries",
    "microsoft.maintenance", "microsoft.sqlvirtualmachine",
}


def _allowed_regions() -> set[str]:
    import os

    raw = os.environ.get("FEDRAMP_VIZ_REGIONS")
    if raw:
        return {r.strip().lower() for r in raw.split(",") if r.strip()}
    return ALLOWED_REGIONS


ALL_TYPES = ["*"]


@rule(
    "AZ-GEN-001",
    "Resource is deployed in a FedRAMP authorized region",
    controls=["SA-9", "SA-9(5)"],
    resource_types=ALL_TYPES,
    severity=Severity.HIGH,
    remediation="Redeploy the resource into a US commercial or Azure Government region inside your authorization boundary. Set FEDRAMP_VIZ_REGIONS to change the allowed list.",
)
def region_authorized(res: Resource):
    """Data must be processed and stored inside the FedRAMP authorization boundary. Azure's authorizations cover US regions only."""
    loc = res.location.lower()
    if loc in GLOBAL_REGIONS:
        if res.type in NO_DATA_GLOBAL_TYPES:
            return not_applicable("Region-less control plane object with no data at rest", location=loc or "global")
        return manual("Global or region-less resource; confirm the backing service stores data in US regions only", location=loc or "global")
    if loc in _allowed_regions():
        return passed(f"Region {loc} is inside the authorization boundary", location=loc)
    return failed(f"Region {loc} is outside the FedRAMP authorization boundary", location=loc)


@rule(
    "AZ-GEN-002",
    "Service is on the Azure services in FedRAMP scope list",
    controls=["SA-9"],
    resource_types=ALL_TYPES,
    severity=Severity.MEDIUM,
    remediation="Check the resource type against Microsoft's 'Azure services in FedRAMP scope' page. Move the workload to an in-scope service or document the risk acceptance.",
)
def service_in_scope(res: Resource):
    """Only services covered by Microsoft's FedRAMP authorization can inherit its controls. Unknown services are flagged for a person to confirm."""
    provider_ns = res.type.split("/")[0]
    if provider_ns in IN_SCOPE_PROVIDERS:
        return passed(f"{provider_ns} is in FedRAMP scope", provider=provider_ns)
    return manual(f"{provider_ns} is not in this tool's in-scope list; confirm against Microsoft's current list", provider=provider_ns)
