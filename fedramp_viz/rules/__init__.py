"""Rule registry.

A rule is a plain function decorated with @rule(...). Importing the provider
packages below registers their rules. To add a check, add a function to the
right module (or a new module imported here) and it shows up everywhere:
CLI, API, dashboard and tests.
"""

from __future__ import annotations

from typing import Callable

from ..models import CheckResult, ImpactLevel, Resource, Rule, Severity

RULES: list[Rule] = []


def rule(
    id: str,
    title: str,
    controls: list[str],
    resource_types: list[str],
    severity: Severity = Severity.MEDIUM,
    min_level: ImpactLevel = ImpactLevel.LOW,
    remediation: str = "",
    provider: str = "azure",
) -> Callable[[Callable[[Resource], CheckResult]], Callable[[Resource], CheckResult]]:
    """Register `fn` as a rule. The function docstring becomes the description."""

    def wrap(fn: Callable[[Resource], CheckResult]) -> Callable[[Resource], CheckResult]:
        if any(r.id == id for r in RULES):
            raise ValueError(f"duplicate rule id {id}")
        RULES.append(
            Rule(
                id=id,
                title=title,
                description=(fn.__doc__ or "").strip(),
                controls=controls,
                resource_types=[t.lower() for t in resource_types],
                check=fn,
                severity=severity,
                min_level=min_level,
                remediation=remediation,
                provider=provider,
            )
        )
        return fn

    return wrap


def all_rules() -> list[Rule]:
    # Importing registers the rules. Kept lazy so the models module has no import cycle.
    from . import azure  # noqa: F401

    return list(RULES)
