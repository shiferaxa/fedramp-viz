"""Virtual machine and managed disk checks."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, not_applicable, passed
from .. import rule
from ._helpers import truthy

VM = ["microsoft.compute/virtualmachines"]
DISK = ["microsoft.compute/disks"]


@rule("AZ-VM-001", "VM uses managed disks", controls=["SC-28"], resource_types=VM, severity=Severity.MEDIUM,
      remediation="Convert to managed disks: az vm convert -g <rg> -n <name>. Managed disks are always encrypted at rest with FIPS validated storage service encryption.")
def managed_disks(res: Resource):
    """Managed disks are encrypted at rest by default. Unmanaged VHDs in a storage account depend on that account's settings and are deprecated."""
    os_disk = res.prop("storageProfile.osDisk") or {}
    if os_disk.get("managedDisk"):
        return passed("OS disk is a managed disk")
    return failed("OS disk is an unmanaged VHD", vhd=(os_disk.get("vhd") or {}).get("uri"))


@rule("AZ-VM-002", "VM has encryption at host", controls=["SC-28", "SC-28(1)"], resource_types=VM, severity=Severity.LOW,
      min_level=ImpactLevel.HIGH,
      remediation="Deallocate the VM, then: az vm update -g <rg> -n <name> --set securityProfile.encryptionAtHost=true (the subscription feature EncryptionAtHost must be registered).")
def encryption_at_host(res: Resource):
    """Encryption at host covers the temp disk and disk caches, which storage service encryption alone does not."""
    v = res.prop("securityProfile.encryptionAtHost")
    return passed("Encryption at host enabled") if truthy(v) else failed("Encryption at host not enabled", encryptionAtHost=v)


@rule("AZ-VM-003", "Linux VM disables password authentication", controls=["IA-5", "AC-17"], resource_types=VM, severity=Severity.MEDIUM,
      remediation="Recreate or update the VM to use SSH keys only (osProfile.linuxConfiguration.disablePasswordAuthentication = true).")
def linux_no_password(res: Resource):
    """Password SSH logins are brute forceable and not tied to a managed key. Key based authentication is expected for remote administration."""
    linux = res.prop("osProfile.linuxConfiguration")
    if linux is None:
        return not_applicable("Not a Linux VM")
    v = linux.get("disablePasswordAuthentication")
    return passed("Password authentication disabled") if truthy(v) else failed("Password authentication is enabled", disablePasswordAuthentication=v)


@rule("AZ-VM-004", "VM uses Trusted Launch or Confidential VM", controls=["SI-7", "SI-7(1)"], resource_types=VM, severity=Severity.LOW,
      min_level=ImpactLevel.MODERATE,
      remediation="Enable Trusted Launch (secure boot and vTPM) on Gen2 VMs: az vm update ... --set securityProfile.securityType=TrustedLaunch securityProfile.uefiSettings.secureBootEnabled=true securityProfile.uefiSettings.vTpmEnabled=true")
def trusted_launch(res: Resource):
    """Secure boot and a virtual TPM give boot integrity verification, which is the software integrity check the control asks for."""
    st = res.prop("securityProfile.securityType")
    if isinstance(st, str) and st.lower() in {"trustedlaunch", "confidentialvm"}:
        return passed(f"Security type {st}", securityType=st)
    return failed("No boot integrity protection (securityType is standard)", securityType=st)


@rule("AZ-DSK-001", "Managed disk is encrypted with a customer managed key", controls=["SC-12", "SC-28(1)"], resource_types=DISK,
      severity=Severity.LOW, min_level=ImpactLevel.HIGH,
      remediation="Create a disk encryption set backed by Key Vault and attach it: az disk update ... --disk-encryption-set <set>")
def disk_cmk(res: Resource):
    """Platform keys meet encryption at rest; customer managed keys add key lifecycle control commonly required for High systems."""
    t = res.prop("encryption.type") or ""
    if "customerkey" in str(t).lower():
        return passed(f"Encryption type {t}", encryptionType=t)
    return failed(f"Encryption type {t or 'EncryptionAtRestWithPlatformKey'}", encryptionType=t)


@rule("AZ-DSK-002", "Managed disk blocks public export and import", controls=["SC-7"], resource_types=DISK,
      severity=Severity.LOW, min_level=ImpactLevel.MODERATE,
      remediation="az disk update ... --network-access-policy DenyAll --public-network-access Disabled")
def disk_no_public_access(res: Resource):
    """Disk SAS export over the public endpoint lets anyone with the URL download the VHD. Deny it unless a migration needs it."""
    policy = res.prop("networkAccessPolicy")
    pna = res.prop("publicNetworkAccess")
    if (isinstance(policy, str) and policy.lower() == "denyall") or (isinstance(pna, str) and pna.lower() == "disabled"):
        return passed("Public export and import blocked", networkAccessPolicy=policy, publicNetworkAccess=pna)
    return failed("Disk can be exported over the public endpoint", networkAccessPolicy=policy, publicNetworkAccess=pna)
