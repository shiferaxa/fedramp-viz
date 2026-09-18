"""Small helpers shared by the Azure rules."""

from __future__ import annotations

from typing import Any

from ...models import Resource


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "enabled", "yes", "on"}
    return bool(value)


def tls_at_least_12(value: Any) -> bool | None:
    """True for TLS 1.2 or 1.3 in any of Azure's spellings, None if unset."""
    if value is None:
        return None
    v = str(value).lower().replace("tls", "").replace("_", "").replace(".", "")
    return v in {"12", "13"}


def network_restricted(res: Resource) -> tuple[bool, dict[str, Any]]:
    """Public network access disabled, or a firewall with default action Deny."""
    pna = res.prop("publicNetworkAccess")
    default_action = res.prop("networkAcls.defaultAction")
    evidence = {"publicNetworkAccess": pna, "networkAcls.defaultAction": default_action}
    if isinstance(pna, str) and pna.lower() == "disabled":
        return True, evidence
    if isinstance(default_action, str) and default_action.lower() == "deny":
        return True, evidence
    return False, evidence


def has_managed_identity(res: Resource) -> bool:
    t = str(res.identity.get("type", "")).lower()
    return "systemassigned" in t or "userassigned" in t
