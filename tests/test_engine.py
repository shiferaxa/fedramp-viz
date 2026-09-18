from pathlib import Path

from fedramp_viz.engine import assess
from fedramp_viz.models import ImpactLevel, Status
from fedramp_viz.providers import FileProvider

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "azure-sample.json"


def load():
    return FileProvider(SAMPLE).resources()


def test_sample_loads():
    resources = load()
    assert len(resources) == 32
    assert all(r.type == r.type.lower() for r in resources)
    assert {r.resource_group for r in resources} >= {"rg-prod-web", "rg-prod-data", "rg-shared-net", "rg-dev"}


def test_levels_are_monotonic():
    resources = load()
    low = assess(resources, ImpactLevel.LOW)
    mod = assess(resources, ImpactLevel.MODERATE)
    high = assess(resources, ImpactLevel.HIGH)
    assert low.summary["rules_active"] <= mod.summary["rules_active"] <= high.summary["rules_active"]
    assert low.summary["fail"] <= mod.summary["fail"] <= high.summary["fail"]
    assert high.summary["deferred"] == 0
    assert low.summary["baseline_controls"] == 156
    assert high.summary["baseline_controls"] == 410
    for a in (low, mod, high):
        assert 0 <= a.summary["score"] <= 100
        assert a.warnings == [], a.warnings


def test_known_findings_present():
    a = assess(load(), ImpactLevel.HIGH)
    fails = {(f.rule_id, f.resource_name) for f in a.findings if f.status == Status.FAIL}
    assert ("AZ-NET-001", "nsg-web") in fails
    assert ("AZ-GEN-001", "vm-dev-01") in fails
    assert ("AZ-AKS-003", "aks-prod-01") in fails
    passes = {(f.rule_id, f.resource_name) for f in a.findings if f.status == Status.PASS}
    assert ("AZ-STG-006", "stproddata001") in passes
    manual = {(f.rule_id, f.resource_name) for f in a.findings if f.status == Status.MANUAL}
    assert ("AZ-GEN-002", "quantum-lab") in manual


def test_roll_ups_consistent():
    a = assess(load(), ImpactLevel.MODERATE)
    d = a.to_dict()
    assert sum(r["fail"] for r in d["resources"]) == d["summary"]["fail"]
    assert sum(g["resources"] for g in d["groups"]) == d["summary"]["resources"]
    failing_controls = {c["id"] for c in d["controls"] if c["status"] == "fail"}
    from_findings = {c for f in d["findings"] if f["status"] == "fail" for c in f["controls"]}
    assert failing_controls == from_findings
    assert d["summary"]["controls_failing"] == len(failing_controls)


def test_check_crash_becomes_manual_not_fatal():
    from fedramp_viz.models import Resource, Rule, Severity

    def boom(res):
        raise KeyError("shape")

    r = Rule(id="T-1", title="t", description="d", controls=["AC-2"], resource_types=["t/x"], check=boom, severity=Severity.LOW)
    res = Resource(id="/a", name="a", type="t/x", location="eastus", resource_group="g", subscription="s")
    a = assess([res], ImpactLevel.LOW, rules=[r])
    assert a.findings[0].status == Status.MANUAL
    assert a.warnings and "KeyError" in a.warnings[0]
