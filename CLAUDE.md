# fedramp-viz

Open source, self hosted scanner that assesses cloud infrastructure (Azure now, GCP and AWS planned) against FedRAMP Rev 5 Low, Moderate and High baselines and serves a dashboard. Python 3.13, FastAPI, vanilla JS frontend, no build step.

## Warnings

* `fedramp_viz/data/controls.json` is generated. Regenerate with `python scripts/build_catalog.py`, never hand edit.
* The dashboard runs under `Content-Security-Policy: default-src 'self'`. No inline `<script>`, no `style=""` attributes in HTML, no CDN. `element.style.x = ...` in JS is fine, `setAttribute("style", ...)` is not.
* Never load resource names into the DOM with innerHTML; the inventory is untrusted input.
* Use the shared venv at `..\.venv` (pip, not uv). Run tests with `..\.venv\Scripts\python -m pytest`.
* Open JSON with `encoding="utf-8"` everywhere; Windows defaults to cp1252 and the NIST catalog contains non ASCII.
* Keep cloud access read only. Any rule or provider that writes to a cloud API is out of scope by design (see SECURITY.md).
* Amha runs `az`, `gcloud`, `aws` and `kubectl` himself in WSL. Give him the command, do not run it.

## Architecture

Data flow: provider (live Resource Graph or exported JSON) -> `Resource` objects -> rules registry -> engine roll ups -> JSON API -> dashboard.

* `fedramp_viz/models.py` Resource, Rule, Finding, ImpactLevel, Status. `Resource.prop()` does case insensitive dotted lookup because Resource Graph and ARM disagree on property casing.
* `fedramp_viz/baselines.py` loads the catalog, converts `SC-7(5)` <-> `sc-7.5`, can override a level from any OSCAL profile.
* `fedramp_viz/rules/__init__.py` `@rule` decorator and registry. `rules/azure/*.py` one module per service, 55 rules. `_helpers.py` shared predicates.
* `fedramp_viz/engine.py` `assess(resources, level)`: keeps a rule if any of its controls is in the baseline, marks it deferred below `min_level`, sets `res.extra["_level"]` so rules can tighten at High, scores pass/fail weighted 3/2/1.
* `fedramp_viz/api.py` FastAPI app, security headers, optional bearer token via `FEDRAMP_VIZ_TOKEN`, in memory cache per level.
* `fedramp_viz/cli.py` `assess`, `serve`, `rules` subcommands.
* `fedramp_viz/web/` index.html, style.css (tokens from the dataviz reference palette, dark mode under both scopes), app.js (SVG family chart, resource map, three tables).
* `baselines/` FedRAMP Rev 5 OSCAL profiles (source of truth for baseline membership).
* `samples/azure-sample.json` synthetic inventory that exercises every rule both ways; tests depend on its counts.

## Commands

```
..\.venv\Scripts\python -m pip install -e ".[dev]"
..\.venv\Scripts\python -m pytest -q
..\.venv\Scripts\python -m fedramp_viz.cli assess --source samples/azure-sample.json --level high
..\.venv\Scripts\python -m fedramp_viz.cli serve --source samples/azure-sample.json --port 8080
python scripts/build_catalog.py          # needs network, downloads the 10 MB NIST catalog to a temp dir
```

Headless screenshot for a visual check (Edge, from Git Bash):
`"/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" --headless=new --no-sandbox --user-data-dir=<scratch> --window-size=1400,1600 --virtual-time-budget=8000 --screenshot=<out.png> http://127.0.0.1:8080/`

## Conventions

* Rule ids are `AZ-<AREA>-<NNN>`; GCP and AWS will use `GCP-` and `AWS-` prefixes.
* Control ids in rules use NIST spelling (`SC-7(5)`); the catalog stores OSCAL spelling (`sc-7.5`).
* `manual` is for "inventory cannot decide", never a soft fail. `not_applicable` is for "wrong OS / wrong level".
* Customer managed key and double encryption rules are `min_level=HIGH`, severity low, and say in the description that they are common High practice rather than a hard FedRAMP requirement.
* Region allow list is US commercial plus Azure Government; override with `FEDRAMP_VIZ_REGIONS`.
* Commits: plain language, no AI attribution, no em dashes (see ~/.claude/CLAUDE.md).

## Current state

v0.1.0 built Sep 17 2026: Azure provider, 55 rules, FedRAMP Rev 5 baselines, dashboard, CLI, Docker, tests (19). Public at github.com/shiferaxa/fedramp-viz (pushed over HTTPS with the Git Credential Manager token; gh CLI is not logged in). Not yet done: diagnostic settings and RBAC checks (need extra Resource Graph tables), GCP and AWS providers, OSCAL assessment results export, accepted risk file, `.gitattributes` for LF line endings.
