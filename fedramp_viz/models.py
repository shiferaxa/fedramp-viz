"""Core data types shared by providers, rules and the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ImpactLevel(str, Enum):
    """FedRAMP impact levels, ordered low < moderate < high."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "moderate": 1, "high": 2}[self.value]

    def at_least(self, other: "ImpactLevel") -> bool:
        return self.rank >= other.rank

    @classmethod
    def parse(cls, value: str) -> "ImpactLevel":
        v = value.strip().lower()
        aliases = {"l": "low", "m": "moderate", "mod": "moderate", "h": "high"}
        return cls(aliases.get(v, v))


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    MANUAL = "manual"  # the check cannot decide from inventory alone; a person confirms
    NA = "not_applicable"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Resource:
    """A cloud resource normalized across providers.

    `properties` keeps the provider's raw property bag so rules can dig into
    provider specific fields. `type` is always lower case.
    """

    id: str
    name: str
    type: str
    location: str
    resource_group: str
    subscription: str
    provider: str = "azure"
    tags: dict[str, str] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)
    sku: dict[str, Any] = field(default_factory=dict)
    kind: str = ""
    identity: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def prop(self, path: str, default: Any = None) -> Any:
        """Dotted lookup into `properties`, case insensitive on each key.

        Azure returns property names in inconsistent casing between Resource
        Graph and the ARM API, so `prop("networkAcls.defaultAction")` also
        matches `networkacls.defaultaction`.
        """
        node: Any = self.properties
        for part in path.split("."):
            if not isinstance(node, dict):
                return default
            match = next((k for k in node if k.lower() == part.lower()), None)
            if match is None:
                return default
            node = node[match]
        return node

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "location": self.location,
            "resource_group": self.resource_group,
            "subscription": self.subscription,
            "provider": self.provider,
            "tags": self.tags,
            "kind": self.kind,
            "sku": self.sku,
        }


@dataclass
class CheckResult:
    status: Status
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


def passed(message: str, **evidence: Any) -> CheckResult:
    return CheckResult(Status.PASS, message, evidence)


def failed(message: str, **evidence: Any) -> CheckResult:
    return CheckResult(Status.FAIL, message, evidence)


def manual(message: str, **evidence: Any) -> CheckResult:
    return CheckResult(Status.MANUAL, message, evidence)


def not_applicable(message: str = "not applicable", **evidence: Any) -> CheckResult:
    return CheckResult(Status.NA, message, evidence)


@dataclass
class Rule:
    """One automated check mapped to NIST SP 800-53 controls.

    `controls` use the catalog spelling, for example "SC-7" or "SC-7(5)".
    `min_level` is the lowest impact level at which the check is enforced;
    below it the rule reports not applicable. The engine also drops any mapped
    control that is not in the selected baseline, so a rule whose controls all
    fall outside the baseline is skipped for that level.
    """

    id: str
    title: str
    description: str
    controls: list[str]
    resource_types: list[str]
    check: Callable[[Resource], CheckResult]
    severity: Severity = Severity.MEDIUM
    min_level: ImpactLevel = ImpactLevel.LOW
    remediation: str = ""
    provider: str = "azure"

    def applies_to(self, resource: Resource) -> bool:
        return resource.provider == self.provider and resource.type in self.resource_types

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "controls": self.controls,
            "resource_types": self.resource_types,
            "severity": self.severity.value,
            "min_level": self.min_level.value,
            "remediation": self.remediation,
            "provider": self.provider,
        }


@dataclass
class Finding:
    rule_id: str
    rule_title: str
    resource_id: str
    resource_name: str
    resource_type: str
    resource_group: str
    location: str
    status: Status
    severity: Severity
    controls: list[str]
    message: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d
