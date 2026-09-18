"""Storage account checks."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, passed
from .. import rule
from ._helpers import network_restricted, tls_at_least_12, truthy

T = ["microsoft.storage/storageaccounts"]


@rule("AZ-STG-001", "Storage account requires HTTPS", controls=["SC-8", "SC-8(1)"], resource_types=T,
      severity=Severity.HIGH, remediation="az storage account update -n <name> -g <rg> --https-only true")
def https_only(res: Resource):
    """Data in transit must be encrypted. Storage accounts can still accept plain HTTP unless secure transfer is required."""
    v = res.prop("supportsHttpsTrafficOnly")
    return passed("Secure transfer required") if truthy(v) else failed("Secure transfer (HTTPS only) is not required", supportsHttpsTrafficOnly=v)


@rule("AZ-STG-002", "Storage account minimum TLS is 1.2", controls=["SC-8(1)", "SC-13"], resource_types=T,
      severity=Severity.HIGH, remediation="az storage account update -n <name> -g <rg> --min-tls-version TLS1_2")
def min_tls(res: Resource):
    """FIPS validated cryptography for data in transit means TLS 1.2 or later. Accounts default to TLS 1.0 unless changed."""
    v = res.prop("minimumTlsVersion")
    ok = tls_at_least_12(v)
    if ok:
        return passed(f"Minimum TLS version is {v}", minimumTlsVersion=v)
    return failed(f"Minimum TLS version is {v or 'unset (TLS 1.0)'}", minimumTlsVersion=v)


@rule("AZ-STG-003", "Blob public (anonymous) access is disabled", controls=["AC-3", "AC-6", "SC-7"], resource_types=T,
      severity=Severity.HIGH, remediation="az storage account update -n <name> -g <rg> --allow-blob-public-access false")
def no_public_blobs(res: Resource):
    """Anonymous read on containers bypasses every access control. Disable it at the account level."""
    v = res.prop("allowBlobPublicAccess")
    if v is False or (isinstance(v, str) and v.lower() == "false"):
        return passed("Anonymous blob access disabled")
    return failed("Anonymous blob access is allowed at the account level", allowBlobPublicAccess=v)


@rule("AZ-STG-004", "Storage account network access is restricted", controls=["SC-7", "SC-7(5)"], resource_types=T,
      severity=Severity.HIGH, min_level=ImpactLevel.MODERATE,
      remediation="Set public network access to Disabled and use private endpoints, or set the firewall default action to Deny and allow only known networks.")
def network_restricted_rule(res: Resource):
    """Deny by default at the boundary. A storage account reachable from any internet address is an unmanaged access point."""
    ok, ev = network_restricted(res)
    return passed("Public network access disabled or firewall default action Deny", **ev) if ok else failed("Reachable from all networks", **ev)


@rule("AZ-STG-005", "Shared key (account key) authorization is disabled", controls=["IA-2", "IA-5", "AC-2"], resource_types=T,
      severity=Severity.MEDIUM, min_level=ImpactLevel.MODERATE,
      remediation="az storage account update -n <name> -g <rg> --allow-shared-key-access false, then use Entra ID (RBAC) or SAS tokens scoped from a user delegation key.")
def no_shared_key(res: Resource):
    """Account keys are shared, non-attributable credentials. Entra ID authorization gives per-identity access and audit trails."""
    v = res.prop("allowSharedKeyAccess")
    if v is False or (isinstance(v, str) and v.lower() == "false"):
        return passed("Shared key access disabled")
    return failed("Shared key access is enabled", allowSharedKeyAccess=v)


@rule("AZ-STG-006", "Storage encryption uses customer managed keys", controls=["SC-12", "SC-28(1)"], resource_types=T,
      severity=Severity.LOW, min_level=ImpactLevel.HIGH,
      remediation="Configure encryption with a Key Vault key (encryption.keySource = Microsoft.Keyvault). Platform keys are FIPS validated; CMK adds your own key lifecycle control, which most High systems require by policy.")
def cmk(res: Resource):
    """Platform managed keys satisfy encryption at rest, but High impact systems commonly require customer controlled key lifecycle."""
    ks = res.prop("encryption.keySource")
    if isinstance(ks, str) and "keyvault" in ks.lower():
        return passed("Customer managed key from Key Vault", keySource=ks)
    return failed("Platform managed keys", keySource=ks)


@rule("AZ-STG-007", "Infrastructure (double) encryption is enabled", controls=["SC-28(1)"], resource_types=T,
      severity=Severity.LOW, min_level=ImpactLevel.HIGH,
      remediation="Infrastructure encryption can only be set at account creation: az storage account create ... --require-infrastructure-encryption true")
def infra_encryption(res: Resource):
    """A second, independent encryption layer at the infrastructure level protects against a compromise of one algorithm or key."""
    v = res.prop("encryption.requireInfrastructureEncryption")
    return passed("Infrastructure encryption enabled") if truthy(v) else failed("Single layer encryption only", requireInfrastructureEncryption=v)
