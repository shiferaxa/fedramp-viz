"""Network boundary checks: NSGs, VNets, NICs."""

from __future__ import annotations

from typing import Any

from ...models import ImpactLevel, Resource, Severity, failed, passed
from .. import rule
from ._helpers import truthy

NSG = ["microsoft.network/networksecuritygroups"]
VNET = ["microsoft.network/virtualnetworks"]
NIC = ["microsoft.network/networkinterfaces"]

INTERNET_SOURCES = {"*", "internet", "0.0.0.0/0", "any", "::/0"}
ADMIN_PORTS = {22, 3389, 5985, 5986}
PLATFORM_SUBNETS = {"gatewaysubnet", "azurebastionsubnet", "azurefirewallsubnet", "azurefirewallmanagementsubnet", "routeserversubnet"}


def _lower(v: Any) -> str:
    return str(v).strip().lower() if v is not None else ""


def _sources(props: dict) -> set[str]:
    out = {_lower(props.get("sourceAddressPrefix"))}
    out.update(_lower(p) for p in props.get("sourceAddressPrefixes") or [])
    out.discard("")
    return out


def _port_ranges(props: dict) -> list[str]:
    ranges = [props.get("destinationPortRange")] + list(props.get("destinationPortRanges") or [])
    return [str(r) for r in ranges if r not in (None, "")]


def _covers_port(ranges: list[str], port: int) -> bool:
    for r in ranges:
        if r == "*":
            return True
        if "-" in r:
            lo, hi = r.split("-", 1)
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return True
        elif r.isdigit() and int(r) == port:
            return True
    return False


def _internet_inbound_allow_rules(res: Resource) -> list[dict]:
    hits = []
    for r in res.prop("securityRules") or []:
        p = r.get("properties", r)
        if _lower(p.get("direction")) != "inbound" or _lower(p.get("access")) != "allow":
            continue
        if _sources(p) & INTERNET_SOURCES:
            hits.append({"name": r.get("name"), "priority": p.get("priority"), "ports": _port_ranges(p), "protocol": p.get("protocol")})
    return hits


@rule("AZ-NET-001", "NSG does not allow management ports from the internet", controls=["SC-7", "SC-7(5)", "AC-17"], resource_types=NSG,
      severity=Severity.HIGH,
      remediation="Remove the inbound rule or restrict its source to a bastion or VPN range. Use Azure Bastion or just-in-time access for SSH and RDP.")
def no_admin_ports_from_internet(res: Resource):
    """SSH, RDP and WinRM open to the internet are the most common path to compromise. Remote access has to come through a managed access point."""
    bad = [h for h in _internet_inbound_allow_rules(res) if any(_covers_port(h["ports"], p) for p in ADMIN_PORTS)]
    if bad:
        names = ", ".join(str(h["name"]) for h in bad)
        return failed(f"Inbound rule(s) allow management ports from the internet: {names}", rules=bad)
    return passed("No inbound rule exposes SSH, RDP or WinRM to the internet")


@rule("AZ-NET-002", "NSG does not allow all ports from the internet", controls=["SC-7", "SC-7(5)"], resource_types=NSG,
      severity=Severity.HIGH,
      remediation="Replace the wildcard rule with explicit allow rules for the ports the workload actually serves.")
def no_any_any_from_internet(res: Resource):
    """Deny all, permit by exception. An allow rule with destination port * from any source is the opposite."""
    bad = [h for h in _internet_inbound_allow_rules(res) if "*" in h["ports"]]
    if bad:
        return failed("Inbound rule(s) allow every port from the internet: " + ", ".join(str(h["name"]) for h in bad), rules=bad)
    return passed("No wildcard inbound allow from the internet")


@rule("AZ-NET-003", "Every workload subnet has a network security group", controls=["SC-7"], resource_types=VNET,
      severity=Severity.MEDIUM,
      remediation="Associate an NSG with each subnet (az network vnet subnet update ... --network-security-group <nsg>). Platform subnets (GatewaySubnet, AzureBastionSubnet, AzureFirewallSubnet) are exempt.")
def subnets_have_nsg(res: Resource):
    """A subnet without an NSG has no traffic filtering at all inside the virtual network boundary."""
    missing = []
    for s in res.prop("subnets") or []:
        name = s.get("name", "")
        if name.lower() in PLATFORM_SUBNETS:
            continue
        p = s.get("properties", {})
        if not p.get("networkSecurityGroup"):
            missing.append(name)
    if missing:
        return failed("Subnets without an NSG: " + ", ".join(missing), subnets=missing)
    return passed("All workload subnets have an NSG")


@rule("AZ-NET-004", "Virtual network has DDoS Network Protection", controls=["SC-5"], resource_types=VNET,
      severity=Severity.MEDIUM, min_level=ImpactLevel.HIGH,
      remediation="Create a DDoS protection plan and enable it on the VNet (az network vnet update ... --ddos-protection true --ddos-protection-plan <plan>).")
def ddos_protection(res: Resource):
    """High impact systems need denial of service protection beyond the free infrastructure tier, which only protects Microsoft's backbone."""
    v = res.prop("enableDdosProtection")
    return passed("DDoS Network Protection enabled") if truthy(v) else failed("DDoS Network Protection not enabled", enableDdosProtection=v)


@rule("AZ-NET-005", "Network interface has no public IP", controls=["SC-7", "SC-7(3)"], resource_types=NIC,
      severity=Severity.MEDIUM, min_level=ImpactLevel.MODERATE,
      remediation="Remove the public IP and reach the VM through Azure Bastion, a load balancer, Application Gateway or a VPN.")
def nic_no_public_ip(res: Resource):
    """Every public IP on a NIC is another external access point. Limit them to a small number of managed entry points."""
    pips = [c.get("properties", {}).get("publicIPAddress", {}).get("id") for c in res.prop("ipConfigurations") or []]
    pips = [p for p in pips if p]
    if pips:
        return failed("NIC has a public IP attached", publicIPAddresses=pips)
    return passed("No public IP on this NIC")
