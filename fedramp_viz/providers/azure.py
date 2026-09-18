"""Live Azure inventory through Azure Resource Graph.

Needs `pip install fedramp-viz[azure]`. Resource Graph is tenant scoped, so the
provider runs the query once per tenant it is told about.

One tenant (default): `DefaultAzureCredential` (az login, environment variables,
managed identity, workload identity). Reader on the subscriptions is enough.

Several tenants from one deployment: set `FEDRAMP_VIZ_TENANTS` (comma separated
tenant ids, or `--tenant` on the CLI) and `FEDRAMP_VIZ_SCAN_CLIENT_ID`, the client
id of a multi tenant app registration whose federated identity credential trusts
this deployment's managed identity. The app's service principal needs Reader in
each tenant. No secret is involved: the managed identity token is exchanged for
an app token per tenant (workload identity federation). Without the client id,
each tenant is read with the signed in az CLI identity, for local runs.
"""

from __future__ import annotations

import os

from ..models import Resource
from .base import Provider, normalize_azure_row

QUERY = (
    "Resources | project id, name, type, location, resourceGroup, "
    "subscriptionId, tenantId, tags, properties, sku, kind, identity"
)
SUBSCRIPTIONS_QUERY = "ResourceContainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId, name"
EXCHANGE_SCOPE = "api://AzureADTokenExchange/.default"


class AzureProvider(Provider):
    name = "azure"

    def __init__(self, subscriptions: list[str] | None = None, tenants: list[str] | None = None,
                 scan_client_id: str | None = None, page_size: int = 1000):
        self.subscriptions = subscriptions
        env_tenants = os.environ.get("FEDRAMP_VIZ_TENANTS", "")
        self.tenants = tenants or [t.strip() for t in env_tenants.split(",") if t.strip()]
        self.scan_client_id = scan_client_id or os.environ.get("FEDRAMP_VIZ_SCAN_CLIENT_ID") or None
        self.page_size = page_size

    def credential(self, tenant: str | None):
        """Credential for one tenant; None means the default single tenant path."""
        from azure.identity import AzureCliCredential, ClientAssertionCredential, DefaultAzureCredential, ManagedIdentityCredential

        if tenant is None:
            return DefaultAzureCredential()
        if self.scan_client_id:
            managed = ManagedIdentityCredential()
            return ClientAssertionCredential(tenant, self.scan_client_id, lambda: managed.get_token(EXCHANGE_SCOPE).token)
        return AzureCliCredential(tenant_id=tenant)

    def resources(self) -> list[Resource]:
        try:
            from azure.mgmt.resourcegraph import ResourceGraphClient
        except ImportError as e:  # pragma: no cover
            raise SystemExit("Azure SDK missing. Run: pip install fedramp-viz[azure]") from e

        out: list[Resource] = []
        for tenant in self.tenants or [None]:
            client = ResourceGraphClient(self.credential(tenant))
            names = {r["subscriptionId"]: r["name"] for r in self._query(client, SUBSCRIPTIONS_QUERY)}
            out.extend(normalize_azure_row(r, names) for r in self._query(client, QUERY))
        return out

    def _query(self, client, query: str) -> list[dict]:
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

        rows: list[dict] = []
        skip_token = None
        while True:
            opts = QueryRequestOptions(top=self.page_size, skip_token=skip_token, result_format="objectArray")
            resp = client.resources(QueryRequest(query=query, subscriptions=self.subscriptions, options=opts))
            rows.extend(resp.data or [])
            skip_token = resp.skip_token
            if not skip_token:
                return rows
