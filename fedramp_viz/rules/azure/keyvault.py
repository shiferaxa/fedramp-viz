"""Key Vault checks."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, passed
from .. import rule
from ._helpers import network_restricted, truthy

T = ["microsoft.keyvault/vaults"]


@rule("AZ-KV-001", "Key Vault soft delete is enabled", controls=["CP-9", "CP-10"], resource_types=T, severity=Severity.MEDIUM,
      remediation="az keyvault update -n <name> --enable-soft-delete true (new vaults have it on and it cannot be turned off).")
def soft_delete(res: Resource):
    """Soft delete keeps deleted keys, secrets and certificates recoverable, which is the backup and recovery expectation for the material that protects everything else."""
    v = res.prop("enableSoftDelete")
    return passed("Soft delete enabled") if truthy(v) else failed("Soft delete disabled", enableSoftDelete=v)


@rule("AZ-KV-002", "Key Vault purge protection is enabled", controls=["CP-9", "SC-12"], resource_types=T, severity=Severity.MEDIUM,
      min_level=ImpactLevel.MODERATE, remediation="az keyvault update -n <name> --enable-purge-protection true (irreversible).")
def purge_protection(res: Resource):
    """Without purge protection a privileged user can permanently destroy keys during the retention window, which also destroys every dataset encrypted with them."""
    v = res.prop("enablePurgeProtection")
    return passed("Purge protection enabled") if truthy(v) else failed("Purge protection disabled", enablePurgeProtection=v)


@rule("AZ-KV-003", "Key Vault uses Azure RBAC for data plane authorization", controls=["AC-3", "AC-6"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.MODERATE, remediation="az keyvault update -n <name> --enable-rbac-authorization true, then assign Key Vault data plane roles.")
def rbac(res: Resource):
    """Access policies are vault local and easy to over grant. RBAC gives centrally managed, least privilege, auditable role assignments."""
    v = res.prop("enableRbacAuthorization")
    return passed("RBAC authorization enabled") if truthy(v) else failed("Legacy access policies in use", enableRbacAuthorization=v)


@rule("AZ-KV-004", "Key Vault network access is restricted", controls=["SC-7", "SC-7(5)"], resource_types=T, severity=Severity.MEDIUM,
      min_level=ImpactLevel.MODERATE,
      remediation="Set public network access to Disabled with a private endpoint, or set the firewall default action to Deny and allow trusted services.")
def network(res: Resource):
    """The vault holding your keys should not answer requests from arbitrary internet addresses."""
    ok, ev = network_restricted(res)
    return passed("Network access restricted", **ev) if ok else failed("Vault is reachable from all networks", **ev)


@rule("AZ-KV-005", "Key Vault is Premium (HSM backed keys)", controls=["SC-12", "SC-13"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.HIGH,
      remediation="Recreate the vault with --sku premium and import or generate HSM protected keys, or use Managed HSM.")
def premium_sku(res: Resource):
    """Premium vaults protect keys in FIPS 140 Level 3 validated HSMs. Standard vaults use software keys in a Level 1 boundary."""
    name = str(res.sku.get("name", "")).lower()
    return passed("Premium SKU") if name == "premium" else failed(f"SKU is {name or 'standard'}", sku=name)
