"""Load an inventory that was exported to JSON.

Accepted shapes:
  * a JSON array of Azure Resource Graph rows
  * {"data": [...]}  (what `az graph query` prints)
  * {"value": [...]} (what `az rest` and ARM list calls print)
  * {"resources": [...], "provider": "azure"}

Export command (anywhere the Azure CLI is signed in, the graph extension installs on first use):

  az graph query -q "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags, properties, sku, kind, identity" --first 1000 -o json > exports/azure.json

Resource Graph pages at 1000 rows. For bigger tenants pass --skip-token, or run
the query once per subscription with --subscriptions and concatenate.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Resource
from .base import Provider, normalize_azure_row


class FileProvider(Provider):
    name = "file"

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def resources(self) -> list[Resource]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        rows = raw
        provider = "azure"
        if isinstance(raw, dict):
            provider = raw.get("provider", "azure")
            rows = raw.get("data") or raw.get("value") or raw.get("resources") or []
        if provider != "azure":
            raise NotImplementedError(f"provider {provider!r} is not supported yet (azure only)")
        return [normalize_azure_row(r) for r in rows]
