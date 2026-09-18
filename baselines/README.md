# Baseline profiles

FedRAMP Rev 5 OSCAL baseline profiles, unmodified, from the OSCAL Foundation mirror of the GSA fedramp-automation content (github.com/OSCAL-Foundation/fedramp-resources, baselines/rev5/json). Version fedramp-3.0.0rc1-oscal-1.1.2, last modified March 2025.

| File | Controls |
|---|---|
| FedRAMP_rev5_LOW-baseline_profile.json | 156 |
| FedRAMP_rev5_MODERATE-baseline_profile.json | 323 |
| FedRAMP_rev5_HIGH-baseline_profile.json | 410 |

`scripts/build_catalog.py` reads these and the NIST SP 800-53 Rev 5 catalog to produce `fedramp_viz/data/controls.json`. Replace the files and rerun the script when FedRAMP publishes a new revision.
