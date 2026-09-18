"""Run the rules against an inventory at a given impact level and score it.

Scoring is deliberately simple and explained in the output:

  * each PASS or FAIL finding carries a weight by severity (high 3, medium 2, low 1)
  * score = weighted passes / weighted (passes + fails), as a percentage
  * MANUAL and NOT_APPLICABLE findings never move the score; they are listed so a
    person can close them out
  * coverage = baseline controls that have at least one automated pass or fail
    finding, divided by the number of controls in the baseline. This is honest
    about how much of a FedRAMP baseline an inventory scan can actually see:
    most controls are policy, process and people, not resource settings.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .baselines import Catalog, load_catalog, to_human_id, to_oscal_id
from .models import Finding, ImpactLevel, Resource, Rule, Severity, Status
from .rules import all_rules

WEIGHTS = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
STATUS_ORDER = {Status.FAIL: 0, Status.MANUAL: 1, Status.PASS: 2, Status.NA: 3}


@dataclass
class Assessment:
    level: ImpactLevel
    generated_at: str
    provider: str
    summary: dict[str, Any]
    families: list[dict[str, Any]]
    controls: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    findings: list[Finding]
    rules: list[dict[str, Any]]
    catalog_source: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "generated_at": self.generated_at,
            "provider": self.provider,
            "summary": self.summary,
            "families": self.families,
            "controls": self.controls,
            "resources": self.resources,
            "groups": self.groups,
            "findings": [f.to_dict() for f in self.findings],
            "rules": self.rules,
            "catalog_source": self.catalog_source,
            "warnings": self.warnings,
        }


def _worst(statuses: list[Status]) -> Status:
    if not statuses:
        return Status.NA
    return min(statuses, key=lambda s: STATUS_ORDER[s])


def assess(
    resources: list[Resource],
    level: ImpactLevel,
    catalog: Catalog | None = None,
    rules: list[Rule] | None = None,
) -> Assessment:
    catalog = catalog or load_catalog()
    rules = rules if rules is not None else all_rules()
    warnings: list[str] = []

    # Work out which rules are live at this level and which of their controls are in the baseline.
    live: list[tuple[Rule, list[str]]] = []
    for r in rules:
        in_baseline = []
        for c in r.controls:
            ctrl = catalog.get(c)
            if ctrl is None:
                warnings.append(f"{r.id}: control {c} not in catalog")
                continue
            if ctrl.in_baseline(level):
                in_baseline.append(ctrl.human_id)
        if in_baseline:
            live.append((r, in_baseline))

    findings: list[Finding] = []
    for res in resources:
        res.extra["_level"] = level.value
        for r, controls in live:
            if not (r.applies_to(res) or ("*" in r.resource_types and res.provider == r.provider)):
                continue
            if not level.at_least(r.min_level):
                findings.append(_finding(r, res, Status.NA, f"Enforced from {r.min_level.value} and above", controls, {"enforced_from": r.min_level.value}))
                continue
            try:
                result = r.check(res)
            except Exception as e:  # a bad property shape must not kill the whole scan
                warnings.append(f"{r.id} on {res.id}: {type(e).__name__}: {e}")
                result_status, msg, ev = Status.MANUAL, f"Check crashed on this resource ({type(e).__name__}); review by hand", {}
            else:
                result_status, msg, ev = result.status, result.message, result.evidence
            findings.append(_finding(r, res, result_status, msg, controls, ev))

    scored = [f for f in findings if f.status in (Status.PASS, Status.FAIL)]
    w_pass = sum(WEIGHTS[f.severity] for f in scored if f.status == Status.PASS)
    w_total = sum(WEIGHTS[f.severity] for f in scored)
    score = round(100 * w_pass / w_total, 1) if w_total else None

    # Per control roll up.
    by_control: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for c in f.controls:
            by_control[to_oscal_id(c)].append(f)

    baseline_controls = catalog.for_level(level)
    control_rows = []
    for ctrl in sorted(baseline_controls, key=_control_sort_key):
        fs = by_control.get(ctrl.id, [])
        statuses = [f.status for f in fs if f.status != Status.NA]
        status = _worst(statuses).value if statuses else "not_assessed"
        control_rows.append({
            "id": ctrl.human_id,
            "title": ctrl.title,
            "family": ctrl.family,
            "status": status,
            "pass": sum(1 for f in fs if f.status == Status.PASS),
            "fail": sum(1 for f in fs if f.status == Status.FAIL),
            "manual": sum(1 for f in fs if f.status == Status.MANUAL),
            "rules": sorted({f.rule_id for f in fs}),
        })

    # Per family roll up (only families present in the baseline).
    fam_rows = []
    for fam_id, fam_name in catalog.families.items():
        rows = [c for c in control_rows if c["family"] == fam_id]
        if not rows:
            continue
        fam_findings = [f for f in findings if f.status != Status.NA and any(catalog.family_of(c) == fam_id for c in f.controls)]
        fam_rows.append({
            "id": fam_id,
            "name": fam_name,
            "controls": len(rows),
            "assessed": sum(1 for c in rows if c["status"] != "not_assessed"),
            "controls_failing": sum(1 for c in rows if c["status"] == "fail"),
            "pass": sum(1 for f in fam_findings if f.status == Status.PASS),
            "fail": sum(1 for f in fam_findings if f.status == Status.FAIL),
            "manual": sum(1 for f in fam_findings if f.status == Status.MANUAL),
        })

    # Per resource roll up.
    by_res: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_res[f.resource_id].append(f)
    res_rows = []
    for res in resources:
        fs = by_res.get(res.id, [])
        row = res.to_dict()
        row.update({
            "status": _worst([f.status for f in fs if f.status != Status.NA]).value if any(f.status != Status.NA for f in fs) else "not_assessed",
            "pass": sum(1 for f in fs if f.status == Status.PASS),
            "fail": sum(1 for f in fs if f.status == Status.FAIL),
            "manual": sum(1 for f in fs if f.status == Status.MANUAL),
            "deferred": sum(1 for f in fs if f.status == Status.NA and f.evidence.get("enforced_from")),
        })
        res_rows.append(row)

    # Resource group names repeat across subscriptions, so groups are keyed by both.
    groups: dict[str, dict[str, Any]] = {}
    for row in res_rows:
        rg = row["resource_group"] or "(none)"
        g = groups.setdefault(f"{row['subscription']}/{rg}", {"name": rg, "subscription": row["subscription"], "subscription_name": row["subscription_name"], "resources": 0, "pass": 0, "fail": 0, "manual": 0})
        g["resources"] += 1
        g["pass"] += row["pass"]
        g["fail"] += row["fail"]
        g["manual"] += row["manual"]

    assessed_controls = sum(1 for c in control_rows if c["status"] in ("pass", "fail"))
    summary = {
        "score": score,
        "resources": len(resources),
        "subscriptions": len({r.subscription for r in resources}),
        "tenants": len({r.tenant for r in resources if r.tenant}),
        "resources_failing": sum(1 for r in res_rows if r["status"] == "fail"),
        "checks": len(scored) + sum(1 for f in findings if f.status == Status.MANUAL),
        "pass": sum(1 for f in findings if f.status == Status.PASS),
        "fail": sum(1 for f in findings if f.status == Status.FAIL),
        "manual": sum(1 for f in findings if f.status == Status.MANUAL),
        "deferred": sum(1 for f in findings if f.status == Status.NA and f.evidence.get("enforced_from")),
        "fail_by_severity": {s.value: sum(1 for f in findings if f.status == Status.FAIL and f.severity == s) for s in Severity},
        "baseline_controls": len(baseline_controls),
        "controls_with_evidence": assessed_controls,
        "controls_failing": sum(1 for c in control_rows if c["status"] == "fail"),
        "coverage": round(100 * assessed_controls / len(baseline_controls), 1) if baseline_controls else 0,
        "rules_active": len(live),
        "rules_total": len(rules),
    }

    return Assessment(
        level=level,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        provider=resources[0].provider if resources else "azure",
        summary=summary,
        families=fam_rows,
        controls=control_rows,
        resources=res_rows,
        groups=sorted(groups.values(), key=lambda g: (-g["fail"], g["name"])),
        findings=sorted(findings, key=lambda f: (STATUS_ORDER[f.status], list(Severity).index(f.severity), f.resource_name, f.rule_id)),
        rules=[dict(r.to_dict(), active=any(r is lr for lr, _ in live)) for r in rules],
        catalog_source=catalog.source,
        warnings=warnings,
    )


def _finding(r: Rule, res: Resource, status: Status, message: str, controls: list[str], evidence: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=r.id,
        rule_title=r.title,
        resource_id=res.id,
        resource_name=res.name,
        resource_type=res.type,
        resource_group=res.resource_group,
        location=res.location,
        subscription=res.subscription,
        status=status,
        severity=r.severity,
        controls=controls,
        message=message,
        remediation=r.remediation,
        evidence=evidence,
    )


def _control_sort_key(ctrl) -> tuple:
    fam, rest = ctrl.id.split("-", 1)
    num, _, enh = rest.partition(".")
    return (fam, int(num), int(enh) if enh else 0)


def levels_summary(resources: list[Resource], catalog: Catalog | None = None) -> dict[str, dict[str, Any]]:
    """Score the same inventory at all three levels, for the level picker."""
    catalog = catalog or load_catalog()
    return {lvl.value: assess(resources, lvl, catalog).summary for lvl in ImpactLevel}


__all__ = ["assess", "Assessment", "levels_summary", "to_human_id"]
