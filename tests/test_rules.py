from fedramp_viz.models import Resource, Status
from fedramp_viz.rules import all_rules


def rule(rid):
    return next(r for r in all_rules() if r.id == rid)


def res(type_, props, **kw):
    return Resource(id="/x", name="x", type=type_, location=kw.pop("location", "eastus"), resource_group="rg", subscription="s", properties=props, **kw)


def test_rule_ids_unique_and_controls_known():
    from fedramp_viz.baselines import load_catalog

    cat = load_catalog()
    rules = all_rules()
    assert len({r.id for r in rules}) == len(rules)
    for r in rules:
        for c in r.controls:
            assert cat.get(c) is not None, f"{r.id} maps to unknown control {c}"
        assert r.description, f"{r.id} has no docstring"
        assert r.remediation, f"{r.id} has no remediation"


def test_storage_https_and_tls():
    r = res("microsoft.storage/storageaccounts", {"supportsHttpsTrafficOnly": False, "minimumTlsVersion": "TLS1_0"})
    assert rule("AZ-STG-001").check(r).status == Status.FAIL
    assert rule("AZ-STG-002").check(r).status == Status.FAIL
    r.properties.update({"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2"})
    assert rule("AZ-STG-001").check(r).status == Status.PASS
    assert rule("AZ-STG-002").check(r).status == Status.PASS


def test_property_lookup_is_case_insensitive():
    r = res("microsoft.storage/storageaccounts", {"networkacls": {"defaultaction": "Deny"}})
    assert rule("AZ-STG-004").check(r).status == Status.PASS


def test_nsg_admin_ports():
    open_ssh = {"securityRules": [{"name": "ssh", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "Internet", "destinationPortRange": "22"}}]}
    assert rule("AZ-NET-001").check(res("microsoft.network/networksecuritygroups", open_ssh)).status == Status.FAIL
    ranged = {"securityRules": [{"name": "r", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefixes": ["0.0.0.0/0"], "destinationPortRanges": ["8000-9000"]}}]}
    assert rule("AZ-NET-001").check(res("microsoft.network/networksecuritygroups", ranged)).status == Status.PASS
    ranged_hit = {"securityRules": [{"name": "r", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRanges": ["3000-4000", "3389"]}}]}
    assert rule("AZ-NET-001").check(res("microsoft.network/networksecuritygroups", ranged_hit)).status == Status.FAIL
    from_vnet = {"securityRules": [{"name": "r", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "10.0.0.0/8", "destinationPortRange": "*"}}]}
    assert rule("AZ-NET-002").check(res("microsoft.network/networksecuritygroups", from_vnet)).status == Status.PASS
    deny = {"securityRules": [{"name": "r", "properties": {"direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*", "destinationPortRange": "*"}}]}
    assert rule("AZ-NET-002").check(res("microsoft.network/networksecuritygroups", deny)).status == Status.PASS


def test_region_rule_and_override(monkeypatch):
    r = res("microsoft.compute/virtualmachines", {}, location="westeurope")
    assert rule("AZ-GEN-001").check(r).status == Status.FAIL
    assert rule("AZ-GEN-001").check(res("microsoft.compute/virtualmachines", {}, location="usgovvirginia")).status == Status.PASS
    assert rule("AZ-GEN-001").check(res("microsoft.network/dnszones", {}, location="global")).status == Status.MANUAL
    monkeypatch.setenv("FEDRAMP_VIZ_REGIONS", "westeurope")
    assert rule("AZ-GEN-001").check(r).status == Status.PASS


def test_linux_password_rule_not_applicable_to_windows():
    win = res("microsoft.compute/virtualmachines", {"osProfile": {"windowsConfiguration": {}}})
    assert rule("AZ-VM-003").check(win).status == Status.NA


def test_aks_api_server_tightens_at_high():
    props = {"apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIPRanges": ["1.2.3.4/32"]}}
    r = res("microsoft.containerservice/managedclusters", props)
    r.extra["_level"] = "moderate"
    assert rule("AZ-AKS-003").check(r).status == Status.PASS
    r.extra["_level"] = "high"
    assert rule("AZ-AKS-003").check(r).status == Status.FAIL


def test_app_min_tls_null_in_export_is_manual():
    # Resource Graph ships siteConfig with every key present and null.
    site = res("microsoft.web/sites", {"siteConfig": {"minTlsVersion": None, "ftpsState": None}})
    assert rule("AZ-APP-002").check(site).status == Status.MANUAL
    assert rule("AZ-APP-002").check(res("microsoft.web/sites", {"siteConfig": None})).status == Status.MANUAL
    assert rule("AZ-APP-002").check(res("microsoft.web/sites", {"siteConfig": {"minTlsVersion": "1.0"}})).status == Status.FAIL
    assert rule("AZ-APP-002").check(res("microsoft.web/sites", {"siteConfig": {"minTlsVersion": "1.2"}})).status == Status.PASS


def test_app_rules_cover_deployment_slots():
    slot = res("microsoft.web/sites/slots", {"httpsOnly": False})
    assert rule("AZ-APP-001").applies_to(slot)
    assert rule("AZ-APP-001").check(slot).status == Status.FAIL


def test_region_rule_skips_regionless_control_plane_objects():
    assert rule("AZ-GEN-001").check(res("microsoft.insights/actiongroups", {}, location="global")).status == Status.NA
    assert rule("AZ-GEN-001").check(res("microsoft.network/trafficmanagerprofiles", {}, location="global")).status == Status.NA


def test_keyvault_soft_delete_unset_is_manual():
    kv = "microsoft.keyvault/vaults"
    assert rule("AZ-KV-001").check(res(kv, {"enableRbacAuthorization": False})).status == Status.MANUAL
    assert rule("AZ-KV-001").check(res(kv, {"enableSoftDelete": False})).status == Status.FAIL
    assert rule("AZ-KV-001").check(res(kv, {"enableSoftDelete": True})).status == Status.PASS


def test_cosmos_private_endpoints_only_passes():
    cosmos = "microsoft.documentdb/databaseaccounts"
    open_acct = {"publicNetworkAccess": "Enabled", "ipRules": [], "virtualNetworkRules": [], "isVirtualNetworkFilterEnabled": False}
    assert rule("AZ-COS-001").check(res(cosmos, open_acct)).status == Status.FAIL
    pe_only = dict(open_acct, privateEndpointConnections=[{"id": "/pe/1"}])
    assert rule("AZ-COS-001").check(res(cosmos, pe_only)).status == Status.PASS


def test_law_retention_bands():
    law = "microsoft.operationalinsights/workspaces"
    assert rule("AZ-LAW-001").check(res(law, {"retentionInDays": 30})).status == Status.FAIL
    mid = res(law, {"retentionInDays": 180})
    mid.extra["_level"] = "moderate"
    assert rule("AZ-LAW-001").check(mid).status == Status.MANUAL
    assert rule("AZ-LAW-001").check(res(law, {"retentionInDays": 365})).status == Status.PASS
