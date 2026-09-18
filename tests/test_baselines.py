import json

import pytest

from fedramp_viz.baselines import load_catalog, load_oscal_profile, to_human_id, to_oscal_id
from fedramp_viz.models import ImpactLevel


def test_id_round_trip():
    assert to_oscal_id("SC-7(5)") == "sc-7.5"
    assert to_oscal_id("sc-7.5") == "sc-7.5"
    assert to_oscal_id("AC-2") == "ac-2"
    assert to_human_id("sc-7.5") == "SC-7(5)"
    assert to_human_id("ac-2") == "AC-2"
    with pytest.raises(ValueError):
        to_oscal_id("nonsense")


def test_catalog_counts():
    cat = load_catalog()
    assert len(cat.families) == 20
    # FedRAMP Rev 5 baseline sizes
    assert len(cat.for_level(ImpactLevel.LOW)) == 156
    assert len(cat.for_level(ImpactLevel.MODERATE)) == 323
    assert len(cat.for_level(ImpactLevel.HIGH)) == 410
    assert cat.get("SC-7(5)").in_baseline(ImpactLevel.MODERATE)
    assert not cat.get("SC-7(5)").in_baseline(ImpactLevel.LOW)
    # FedRAMP adds encryption in transit and at rest to Low; plain NIST Low does not have them
    assert cat.get("SC-8").in_baseline(ImpactLevel.LOW)
    assert cat.get("SC-8(1)").in_baseline(ImpactLevel.LOW)
    assert cat.get("SC-28").in_baseline(ImpactLevel.LOW)
    assert cat.family_of("SC-7") == "SC"


def test_oscal_profile_override(tmp_path):
    cat = load_catalog()
    profile = {"profile": {"imports": [{"include-controls": [{"with-ids": ["ac-1", "sc-8", "zz-99"]}]}]}}
    p = tmp_path / "profile.json"
    p.write_text(json.dumps(profile), encoding="utf-8")
    load_oscal_profile(cat, p, ImpactLevel.LOW)
    low = {c.id for c in cat.for_level(ImpactLevel.LOW)}
    assert low == {"ac-1", "sc-8", "zz-99"}
    assert cat.get("zz-99").family == "ZZ"
    # other levels untouched
    assert len(cat.for_level(ImpactLevel.HIGH)) == 410
