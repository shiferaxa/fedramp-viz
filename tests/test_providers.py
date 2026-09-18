import pytest

from fedramp_viz.providers.azure import AzureProvider
from fedramp_viz.providers.base import normalize_azure_row


def test_normalize_row_carries_tenant_and_subscription_name():
    row = {
        "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a",
        "name": "a", "type": "Microsoft.Storage/storageAccounts", "location": "EastUS2", "tenantId": "t1",
    }
    r = normalize_azure_row(row, {"s1": "Prod"})
    assert (r.subscription, r.subscription_name, r.tenant, r.resource_group) == ("s1", "Prod", "t1", "rg")
    assert r.to_dict()["subscription_name"] == "Prod"
    assert normalize_azure_row(row).subscription_name == ""


def test_credential_selection(monkeypatch):
    identity = pytest.importorskip("azure.identity")
    monkeypatch.delenv("FEDRAMP_VIZ_TENANTS", raising=False)
    monkeypatch.delenv("FEDRAMP_VIZ_SCAN_CLIENT_ID", raising=False)
    single = AzureProvider()
    assert single.tenants == [] and single.scan_client_id is None
    assert isinstance(single.credential(None), identity.DefaultAzureCredential)
    # tenants without a scanner app: the signed in CLI identity, one token per tenant
    assert isinstance(AzureProvider(tenants=["t1"]).credential("t1"), identity.AzureCliCredential)
    # deployed multi tenant mode: managed identity exchanged for the scanner app, no secret
    monkeypatch.setenv("FEDRAMP_VIZ_TENANTS", "t1, t2")
    monkeypatch.setenv("FEDRAMP_VIZ_SCAN_CLIENT_ID", "client")
    multi = AzureProvider()
    assert multi.tenants == ["t1", "t2"] and multi.scan_client_id == "client"
    assert isinstance(multi.credential("t1"), identity.ClientAssertionCredential)
