"""Live Azure inventory through Azure Resource Graph.

Needs `pip install fedramp-viz[azure]` and a signed in identity that
DefaultAzureCredential can find (az login, environment variables, managed
identity). Reader on the subscriptions is enough; Resource Graph is read only.
"""

from __future__ import annotations

from ..models import Resource
from .base import Provider, normalize_azure_row

QUERY = (
    "Resources | project id, name, type, location, resourceGroup, "
    "subscriptionId, tags, properties, sku, kind, identity"
)


class AzureProvider(Provider):
    name = "azure"

    def __init__(self, subscriptions: list[str] | None = None, page_size: int = 1000):
        self.subscriptions = subscriptions
        self.page_size = page_size

    def resources(self) -> list[Resource]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resourcegraph import ResourceGraphClient
            from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
        except ImportError as e:  # pragma: no cover
            raise SystemExit("Azure SDK missing. Run: pip install fedramp-viz[azure]") from e

        client = ResourceGraphClient(DefaultAzureCredential())
        rows: list[dict] = []
        skip_token = None
        while True:
            opts = QueryRequestOptions(top=self.page_size, skip_token=skip_token, result_format="objectArray")
            req = QueryRequest(query=QUERY, subscriptions=self.subscriptions, options=opts)
            resp = client.resources(req)
            rows.extend(resp.data or [])
            skip_token = resp.skip_token
            if not skip_token:
                break
        return [normalize_azure_row(r) for r in rows]
