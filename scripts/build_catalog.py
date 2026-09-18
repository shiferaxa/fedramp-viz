"""Regenerate fedramp_viz/data/controls.json.

Inputs:
  * NIST SP 800-53 Rev 5 OSCAL catalog (downloaded to a temp dir, 10 MB, not kept)
  * FedRAMP Rev 5 LOW, MODERATE and HIGH OSCAL baseline profiles in baselines/

Output: a compact catalog with id, title, family, baseline membership and the
withdrawn flag for every control and enhancement. The dashboard and engine read
only this file. Run from the repo root:

  python scripts/build_catalog.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINES = ROOT / "baselines"
OUT = ROOT / "fedramp_viz" / "data" / "controls.json"
NIST_CATALOG = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
LEVELS = {"low": "LOW", "moderate": "MODERATE", "high": "HIGH"}


def profile_ids(path: Path) -> set[str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for imp in raw["profile"].get("imports", []):
        for inc in imp.get("include-controls", []):
            ids.update(i.lower() for i in inc.get("with-ids", []))
    return ids


def main() -> int:
    baselines = {lvl: profile_ids(BASELINES / f"FedRAMP_rev5_{tag}-baseline_profile.json") for lvl, tag in LEVELS.items()}
    with tempfile.TemporaryDirectory() as tmp:
        cat_path = Path(tmp) / "catalog.json"
        print("downloading NIST catalog ...")
        urllib.request.urlretrieve(NIST_CATALOG, cat_path)
        catalog = json.loads(cat_path.read_text(encoding="utf-8"))["catalog"]

    families: dict[str, str] = {}
    controls: dict[str, dict] = {}

    def walk(items, fam):
        for c in items:
            cid = c["id"].lower()
            withdrawn = any(p.get("name") == "status" and p.get("value") == "withdrawn" for p in c.get("props", []))
            controls[cid] = {
                "id": cid.upper(),
                "title": c["title"],
                "family": fam,
                "baselines": [lvl for lvl in LEVELS if cid in baselines[lvl]],
                "withdrawn": withdrawn,
            }
            walk(c.get("controls", []), fam)

    for g in catalog["groups"]:
        families[g["id"].upper()] = g["title"]
        walk(g.get("controls", []), g["id"].upper())

    missing = sorted({i for ids in baselines.values() for i in ids if i not in controls})
    if missing:
        print("baseline ids missing from the NIST catalog:", missing, file=sys.stderr)
        return 1

    out = {
        "source": "FedRAMP Rev 5 LOW/MODERATE/HIGH baseline profiles (OSCAL, OSCAL-Foundation/fedramp-resources mirror of GSA fedramp-automation) applied to the NIST SP 800-53 Rev 5 OSCAL catalog (usnistgov/oscal-content). Regenerate with scripts/build_catalog.py.",
        "families": families,
        "controls": list(controls.values()),
    }
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8")
    counts = {lvl: sum(1 for c in controls.values() if lvl in c["baselines"]) for lvl in LEVELS}
    print(f"wrote {OUT} with {len(controls)} controls in {len(families)} families; baseline sizes {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
