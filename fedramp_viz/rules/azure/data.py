"""Other data services: Cosmos DB, PostgreSQL flexible server, Redis, Container Registry."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, passed
from .. import rule
from ._helpers import tls_at_least_12, truthy

COSMOS = ["microsoft.documentdb/databaseaccounts"]
PG = ["microsoft.dbforpostgresql/flexibleservers"]
REDIS = ["microsoft.cache/redis"]
ACR = ["microsoft.containerregistry/registries"]


def _disabled(v) -> bool:
    return isinstance(v, str) and v.lower() == "disabled"


# Cosmos DB


@rule("AZ-COS-001", "Cosmos DB account network access is restricted", controls=["SC-7", "SC-7(5)"], resource_types=COSMOS,
      severity=Severity.HIGH, min_level=ImpactLevel.MODERATE,
      remediation="Disable public network access and use private endpoints, or enable the VNet filter with explicit virtual network and IP rules.")
def cosmos_network(res: Resource):
    """An account open to all networks relies on keys alone as its boundary. An account with private endpoints and no IP or virtual network rules is reachable only through those endpoints, whatever publicNetworkAccess says."""
    pna = res.prop("publicNetworkAccess")
    vnet_filter = truthy(res.prop("isVirtualNetworkFilterEnabled"))
    ip_rules = res.prop("ipRules") or []
    private_endpoints = res.prop("privateEndpointConnections") or []
    if _disabled(pna):
        return passed("Public network access disabled", publicNetworkAccess=pna)
    if vnet_filter or ip_rules:
        return passed("Network filter with explicit rules", ipRules=len(ip_rules), isVirtualNetworkFilterEnabled=vnet_filter)
    if private_endpoints:
        return passed("Private endpoints only (no public IP or virtual network rules)", privateEndpointConnections=len(private_endpoints), publicNetworkAccess=pna)
    return failed("Account accepts connections from all networks", publicNetworkAccess=pna)


@rule("AZ-COS-002", "Cosmos DB minimum TLS is 1.2", controls=["SC-8(1)", "SC-13"], resource_types=COSMOS, severity=Severity.HIGH,
      remediation="az cosmosdb update ... --minimal-tls-version Tls12")
def cosmos_tls(res: Resource):
    """Data in transit must use TLS 1.2 or later."""
    v = res.prop("minimalTlsVersion")
    return passed(f"Minimum TLS {v}") if tls_at_least_12(v) else failed(f"Minimum TLS is {v or 'unset'}", minimalTlsVersion=v)


@rule("AZ-COS-003", "Cosmos DB key based (local) authentication is disabled", controls=["IA-2", "IA-5"], resource_types=COSMOS,
      severity=Severity.LOW, min_level=ImpactLevel.MODERATE,
      remediation="az cosmosdb update ... --disable-key-based-metadata-write-access true and set properties.disableLocalAuth = true; move clients to Entra ID RBAC.")
def cosmos_local_auth(res: Resource):
    """Account keys are shared secrets with full access. Entra ID gives per identity, revocable access."""
    v = res.prop("disableLocalAuth")
    return passed("Local authentication disabled") if truthy(v) else failed("Account keys accepted", disableLocalAuth=v)


@rule("AZ-COS-004", "Cosmos DB backups are continuous or geo redundant", controls=["CP-9", "CP-6"], resource_types=COSMOS,
      severity=Severity.LOW, min_level=ImpactLevel.MODERATE,
      remediation="Switch to continuous backup, or set periodic backup storage redundancy to Geo or Zone.")
def cosmos_backup(res: Resource):
    """Backups stored in a single locale do not survive a regional loss. Continuous backup or geo redundant periodic backup does."""
    policy = res.prop("backupPolicy") or {}
    t = str(policy.get("type", "")).lower()
    red = str(policy.get("periodicModeProperties", {}).get("backupStorageRedundancy", "")).lower()
    if t == "continuous" or red in {"geo", "zone"}:
        return passed(f"Backup {t or 'periodic'} {red}".strip(), type=t, redundancy=red)
    return failed(f"Backup is {t or 'periodic'} with {red or 'local'} redundancy", type=t, redundancy=red)


# PostgreSQL flexible server


@rule("AZ-PG-001", "PostgreSQL server public network access is disabled", controls=["SC-7", "SC-7(5)"], resource_types=PG,
      severity=Severity.HIGH, min_level=ImpactLevel.MODERATE,
      remediation="Recreate with VNet integration (delegated subnet) or add a private endpoint and disable public access.")
def pg_network(res: Resource):
    """Database endpoints belong inside the boundary, not on the internet behind firewall rules."""
    v = res.prop("network.publicNetworkAccess")
    return passed("Public network access disabled") if _disabled(v) else failed("Public network access enabled", publicNetworkAccess=v)


@rule("AZ-PG-002", "PostgreSQL data encryption uses a customer managed key", controls=["SC-12", "SC-28(1)"], resource_types=PG,
      severity=Severity.LOW, min_level=ImpactLevel.HIGH,
      remediation="Enable data encryption with a Key Vault key and a user assigned identity (dataEncryption.type = AzureKeyVault).")
def pg_cmk(res: Resource):
    """Customer managed keys give the key lifecycle control High systems typically require."""
    t = res.prop("dataEncryption.type")
    return passed("Customer managed key", type=t) if str(t).lower() == "azurekeyvault" else failed("System managed key", type=t)


@rule("AZ-PG-003", "PostgreSQL backups are geo redundant", controls=["CP-9", "CP-6"], resource_types=PG,
      severity=Severity.LOW, min_level=ImpactLevel.HIGH,
      remediation="Geo redundant backup can only be set at creation: az postgres flexible-server create ... --geo-redundant-backup Enabled")
def pg_geo_backup(res: Resource):
    """Backups must survive the loss of the primary region."""
    v = res.prop("backup.geoRedundantBackup")
    return passed("Geo redundant backup enabled") if truthy(v) else failed("Backups are locally redundant only", geoRedundantBackup=v)


# Redis


@rule("AZ-RED-001", "Redis non SSL port is disabled", controls=["SC-8", "SC-8(1)"], resource_types=REDIS, severity=Severity.HIGH,
      remediation="az redis update ... --set enableNonSslPort=false")
def redis_ssl(res: Resource):
    """Port 6379 carries data and credentials in plain text."""
    v = res.prop("enableNonSslPort")
    return failed("Plain text port 6379 enabled", enableNonSslPort=v) if truthy(v) else passed("Only the TLS port is enabled")


@rule("AZ-RED-002", "Redis minimum TLS is 1.2", controls=["SC-8(1)", "SC-13"], resource_types=REDIS, severity=Severity.HIGH,
      remediation="az redis update ... --set minimumTlsVersion=1.2")
def redis_tls(res: Resource):
    """TLS 1.0 and 1.1 are not FIPS acceptable."""
    v = res.prop("minimumTlsVersion")
    return passed(f"Minimum TLS {v}") if tls_at_least_12(v) else failed(f"Minimum TLS is {v or 'unset'}", minimumTlsVersion=v)


@rule("AZ-RED-003", "Redis public network access is disabled", controls=["SC-7"], resource_types=REDIS, severity=Severity.MEDIUM,
      min_level=ImpactLevel.HIGH, remediation="Add a private endpoint and set publicNetworkAccess to Disabled.")
def redis_network(res: Resource):
    """A cache on the public internet exposes session and application data to credential attacks."""
    v = res.prop("publicNetworkAccess")
    return passed("Public network access disabled") if _disabled(v) else failed("Public network access enabled", publicNetworkAccess=v)


# Container Registry


@rule("AZ-ACR-001", "Container registry admin user is disabled", controls=["IA-2", "AC-2", "AC-6"], resource_types=ACR, severity=Severity.MEDIUM,
      remediation="az acr update -n <name> --admin-enabled false; pull with managed identities or Entra tokens instead.")
def acr_admin(res: Resource):
    """The admin user is a single shared password with push and pull rights, not tied to any person."""
    v = res.prop("adminUserEnabled")
    return failed("Admin user enabled", adminUserEnabled=v) if truthy(v) else passed("Admin user disabled")


@rule("AZ-ACR-002", "Container registry public network access is disabled", controls=["SC-7"], resource_types=ACR, severity=Severity.MEDIUM,
      min_level=ImpactLevel.HIGH, remediation="Premium SKU with a private endpoint: az acr update -n <name> --public-network-enabled false")
def acr_network(res: Resource):
    """Registries hold your deployable artifacts; pulling and pushing should stay inside the boundary."""
    v = res.prop("publicNetworkAccess")
    return passed("Public network access disabled") if _disabled(v) else failed("Public network access enabled", publicNetworkAccess=v)
