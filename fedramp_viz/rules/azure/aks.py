"""Azure Kubernetes Service checks."""

from __future__ import annotations

from ...models import ImpactLevel, Resource, Severity, failed, passed
from .. import rule
from ._helpers import truthy

T = ["microsoft.containerservice/managedclusters"]


@rule("AZ-AKS-001", "AKS uses Entra ID with Azure RBAC for Kubernetes authorization", controls=["AC-2", "AC-3", "IA-2"], resource_types=T,
      severity=Severity.HIGH,
      remediation="az aks update -g <rg> -n <name> --enable-aad --enable-azure-rbac")
def entra_rbac(res: Resource):
    """Cluster users must be identities from your directory with centrally managed roles, not static kubeconfig certificates."""
    managed = truthy(res.prop("aadProfile.managed"))
    azure_rbac = truthy(res.prop("aadProfile.enableAzureRBAC"))
    if managed and azure_rbac:
        return passed("Entra ID integration with Azure RBAC")
    if managed:
        return failed("Entra ID integrated but Kubernetes RBAC only (no Azure RBAC)", managed=managed, enableAzureRBAC=azure_rbac)
    return failed("No Entra ID integration", managed=managed, enableAzureRBAC=azure_rbac)


@rule("AZ-AKS-002", "AKS local accounts are disabled", controls=["IA-2", "AC-2"], resource_types=T, severity=Severity.MEDIUM,
      min_level=ImpactLevel.MODERATE, remediation="az aks update -g <rg> -n <name> --disable-local-accounts")
def local_accounts(res: Resource):
    """The clusterAdmin local credential is a non expiring certificate outside identity management."""
    v = res.prop("disableLocalAccounts")
    return passed("Local accounts disabled") if truthy(v) else failed("Local (certificate) accounts enabled", disableLocalAccounts=v)


@rule("AZ-AKS-003", "AKS API server is private or IP restricted", controls=["SC-7", "SC-7(5)"], resource_types=T, severity=Severity.HIGH,
      min_level=ImpactLevel.MODERATE,
      remediation="Create a private cluster (--enable-private-cluster) or at minimum set --api-server-authorized-ip-ranges. High requires private.")
def api_server(res: Resource):
    """The API server is the control plane of everything you run; on the public internet it is a permanent target. High systems need it private."""
    private = truthy(res.prop("apiServerAccessProfile.enablePrivateCluster"))
    ranges = res.prop("apiServerAccessProfile.authorizedIPRanges") or []
    if private:
        return passed("Private cluster")
    if ranges:
        return passed(f"Authorized IP ranges ({len(ranges)})", authorizedIPRanges=ranges) if _level_below_high(res) else failed("Public API server with IP allow list; High requires a private cluster", authorizedIPRanges=ranges)
    return failed("API server is public with no IP restriction")


def _level_below_high(res: Resource) -> bool:
    # The engine stores the level being assessed on the resource's extra bag so
    # rules that tighten at High can branch. Defaults to moderate behaviour.
    return res.extra.get("_level") != "high"


@rule("AZ-AKS-004", "AKS has a network policy engine", controls=["SC-7", "AC-4"], resource_types=T, severity=Severity.MEDIUM,
      min_level=ImpactLevel.MODERATE,
      remediation="Set at creation: az aks create ... --network-policy azure (or cilium). Existing clusters: az aks update --network-policy.")
def network_policy(res: Resource):
    """Without a policy engine every pod can talk to every other pod; there is no enforceable flow control inside the cluster."""
    v = res.prop("networkProfile.networkPolicy")
    if isinstance(v, str) and v.lower() in {"azure", "calico", "cilium"}:
        return passed(f"Network policy {v}", networkPolicy=v)
    return failed("No network policy engine", networkPolicy=v)


@rule("AZ-AKS-005", "AKS sends control plane and container logs to Azure Monitor", controls=["AU-2", "AU-12", "SI-4"], resource_types=T,
      severity=Severity.MEDIUM,
      remediation="az aks enable-addons -a monitoring -g <rg> -n <name> --workspace-resource-id <law>, and add a diagnostic setting for kube-audit.")
def monitoring(res: Resource):
    """Audit records and container logs need to be generated and shipped somewhere durable and central."""
    oms = truthy(res.prop("addonProfiles.omsagent.enabled"))
    metrics = truthy(res.prop("azureMonitorProfile.metrics.enabled"))
    if oms:
        return passed("Container insights enabled", metrics=metrics)
    return failed("Container insights (omsagent) not enabled", omsagent=oms, metrics=metrics)


@rule("AZ-AKS-006", "AKS has Defender for Containers enabled", controls=["SI-4", "RA-5"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.MODERATE,
      remediation="az aks update -g <rg> -n <name> --enable-defender")
def defender(res: Resource):
    """Runtime threat detection and vulnerability scanning of the node and workloads."""
    v = res.prop("securityProfile.defender.securityMonitoring.enabled")
    return passed("Defender for Containers enabled") if truthy(v) else failed("Defender for Containers not enabled", enabled=v)


@rule("AZ-AKS-007", "AKS has the Azure Policy add-on", controls=["CM-6", "CM-7"], resource_types=T, severity=Severity.LOW,
      min_level=ImpactLevel.MODERATE, remediation="az aks enable-addons -a azure-policy -g <rg> -n <name>")
def policy_addon(res: Resource):
    """The policy add-on enforces configuration baselines (no privileged pods, allowed registries) on admission."""
    v = res.prop("addonProfiles.azurepolicy.enabled")
    return passed("Azure Policy add-on enabled") if truthy(v) else failed("Azure Policy add-on not enabled", enabled=v)


@rule("AZ-AKS-008", "AKS secrets are encrypted in etcd with a Key Vault key (KMS)", controls=["SC-12", "SC-28(1)"], resource_types=T,
      severity=Severity.LOW, min_level=ImpactLevel.HIGH,
      remediation="az aks update -g <rg> -n <name> --enable-azure-keyvault-kms --azure-keyvault-kms-key-id <key>")
def kms(res: Resource):
    """Kubernetes secrets sit in etcd; KMS wraps them with your own key instead of the platform's."""
    v = res.prop("securityProfile.azureKeyVaultKms.enabled")
    return passed("KMS etcd encryption enabled") if truthy(v) else failed("Secrets in etcd use platform encryption only", enabled=v)
