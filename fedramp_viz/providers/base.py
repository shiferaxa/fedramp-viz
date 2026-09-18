from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import Resource


class Provider(ABC):
    name = "base"

    @abstractmethod
    def resources(self) -> list[Resource]: ...


_KNOWN = {"id", "name", "type", "location", "resourceGroup", "subscriptionId", "tags", "properties", "sku", "kind", "identity"}


def normalize_azure_row(row: dict[str, Any]) -> Resource:
    """Turn an Azure Resource Graph row (or an `az resource show` object) into a Resource."""
    rid = row.get("id", "")
    parts = rid.split("/")
    rg = row.get("resourceGroup") or (parts[4] if len(parts) > 4 and parts[3].lower() == "resourcegroups" else "")
    sub = row.get("subscriptionId") or (parts[2] if len(parts) > 2 and parts[1].lower() == "subscriptions" else "")
    return Resource(
        id=rid,
        name=row.get("name", ""),
        type=(row.get("type") or "").lower(),
        location=(row.get("location") or "").lower(),
        resource_group=rg,
        subscription=sub,
        provider="azure",
        tags=row.get("tags") or {},
        properties=row.get("properties") or {},
        sku=row.get("sku") or {},
        kind=row.get("kind") or "",
        identity=row.get("identity") or {},
        extra={k: v for k, v in row.items() if k not in _KNOWN},
    )
