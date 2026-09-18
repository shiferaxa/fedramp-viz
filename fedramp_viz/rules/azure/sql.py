"""Azure SQL logical server checks."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, passed
from .. import rule
from ._helpers import tls_at_least_12, truthy

T = ["microsoft.sql/servers"]


@rule("AZ-SQL-001", "SQL server minimum TLS is 1.2", controls=["SC-8(1)", "SC-13"], resource_types=T, severity=Severity.HIGH,
      remediation="az sql server update -g <rg> -n <name> --minimal-tls-version 1.2")
def min_tls(res: Resource):
    """Connections must negotiate TLS 1.2 or later so only FIPS validated cipher suites are used."""
    v = res.prop("minimalTlsVersion")
    return passed(f"Minimum TLS {v}") if tls_at_least_12(v) else failed(f"Minimum TLS is {v or 'unset'}", minimalTlsVersion=v)


@rule("AZ-SQL-002", "SQL server public network access is disabled", controls=["SC-7", "SC-7(5)"], resource_types=T, severity=Severity.HIGH,
      min_level=ImpactLevel.MODERATE,
      remediation="az sql server update ... --enable-public-network false and add a private endpoint.")
def public_access(res: Resource):
    """A database endpoint on the internet, even behind firewall rules, is outside a deny by default boundary."""
    v = res.prop("publicNetworkAccess")
    if isinstance(v, str) and v.lower() == "disabled":
        return passed("Public network access disabled")
    return failed("Public network access enabled", publicNetworkAccess=v)


@rule("AZ-SQL-003", "SQL server uses Entra ID only authentication", controls=["IA-2", "IA-5"], resource_types=T, severity=Severity.MEDIUM,
      min_level=ImpactLevel.MODERATE,
      remediation="az sql server ad-only-auth enable -g <rg> -n <name> after setting an Entra admin.")
def entra_only(res: Resource):
    """SQL logins are local passwords outside your identity provider, with no MFA and no central lifecycle. Entra only authentication removes them."""
    v = res.prop("administrators.azureADOnlyAuthentication")
    return passed("Entra ID only authentication") if truthy(v) else failed("SQL authentication (local logins) still allowed", azureADOnlyAuthentication=v)


@rule("AZ-SQL-004", "SQL server TDE protector is a customer managed key", controls=["SC-12", "SC-28(1)"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.HIGH,
      remediation="Assign a managed identity, grant it wrap/unwrap on a Key Vault key and set it as the encryption protector (az sql server tde-key set).")
def tde_cmk(res: Resource):
    """Transparent data encryption is always on with service managed keys; High systems commonly require the protector to be a customer key."""
    key = res.prop("keyId")
    return passed("Customer managed TDE protector", keyId=key) if key else failed("Service managed TDE protector", keyId=key)
