"""Command line entry point.

  fedramp-viz assess --source samples/azure-sample.json --level high
  fedramp-viz assess --source azure --level moderate --json report.json
  fedramp-viz serve  --source exports/azure.json --port 8080
  fedramp-viz rules
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .baselines import load_catalog, load_oscal_profile
from .engine import assess
from .models import ImpactLevel, Status
from .providers import get_provider
from .rules import all_rules


def _catalog(args):
    catalog = load_catalog(args.catalog) if getattr(args, "catalog", None) else load_catalog()
    for spec in getattr(args, "oscal_profile", None) or []:
        level, _, path = spec.partition("=")
        if not path:
            sys.exit("--oscal-profile takes level=path, for example high=FedRAMP_rev5_HIGH-baseline_profile.json")
        load_oscal_profile(catalog, path, ImpactLevel.parse(level))
    return catalog


def _provider(args):
    kwargs = {}
    if args.source == "azure":
        if args.subscription:
            kwargs["subscriptions"] = args.subscription
        if args.tenant:
            kwargs["tenants"] = args.tenant
    return get_provider(args.source, **kwargs)


def cmd_assess(args) -> int:
    level = ImpactLevel.parse(args.level)
    resources = _provider(args).resources()
    result = assess(resources, level, _catalog(args))
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    s = result.summary
    print(f"fedramp-viz  level={level.value}  resources={s['resources']}  rules active={s['rules_active']}/{s['rules_total']}")
    print(f"score {s['score']}%   pass {s['pass']}  fail {s['fail']}  manual {s['manual']}  deferred to higher level {s['deferred']}")
    print(f"baseline controls {s['baseline_controls']}, with automated evidence {s['controls_with_evidence']} ({s['coverage']}%), failing {s['controls_failing']}")
    print()
    fails = [f for f in result.findings if f.status == Status.FAIL]
    if fails:
        print("Failing checks")
        width = max(len(f.rule_id) for f in fails)
        for f in fails:
            print(f"  {f.rule_id:<{width}}  {f.severity.value:<6}  {f.resource_name:<24} {f.message}")
    manual = [f for f in result.findings if f.status == Status.MANUAL]
    if manual:
        print()
        print(f"Manual review ({len(manual)})")
        for f in manual[: args.limit]:
            print(f"  {f.rule_id:<12}  {f.resource_name:<24} {f.message}")
        if len(manual) > args.limit:
            print(f"  ... {len(manual) - args.limit} more, see --json output")
    for w in result.warnings:
        print("warning:", w, file=sys.stderr)
    if args.json:
        print(f"\nfull report written to {args.json}")
    return 1 if fails and args.fail_on_findings else 0


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        sys.exit("uvicorn is not installed; pip install fedramp-viz")
    from .api import create_app

    app = create_app(_provider(args), _catalog(args))
    state = app.state.assessment_state
    print(f"scanned {len(state.resources)} resources across {len({r.subscription for r in state.resources})} subscription(s)")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: binding to {args.host}. Put a reverse proxy with TLS in front and set FEDRAMP_VIZ_TOKEN.", file=sys.stderr)
    print(f"dashboard on http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_rules(args) -> int:
    rules = all_rules()
    if args.json:
        print(json.dumps([r.to_dict() for r in rules], indent=2))
        return 0
    for r in rules:
        print(f"{r.id:<12} {r.severity.value:<6} from {r.min_level.value:<8} {', '.join(r.controls):<28} {r.title}")
    print(f"\n{len(rules)} rules")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fedramp-viz", description="Assess cloud infrastructure against FedRAMP baselines.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--source", required=True, help="'azure' for a live Resource Graph query, or a path to an exported JSON inventory")
        sp.add_argument("--subscription", action="append", help="limit a live azure scan to this subscription id (repeatable)")
        sp.add_argument("--tenant", action="append", help="tenant id to scan, one Resource Graph query each (repeatable; default: the signed in identity's tenant)")
        sp.add_argument("--catalog", help="alternate controls.json")
        sp.add_argument("--oscal-profile", action="append", metavar="LEVEL=PATH", help="override a baseline from an OSCAL profile, e.g. high=FedRAMP_rev5_HIGH-baseline_profile.json")

    a = sub.add_parser("assess", help="run the checks once and print a summary")
    common(a)
    a.add_argument("--level", default="moderate", help="low, moderate or high (default moderate)")
    a.add_argument("--json", help="write the full report to this file")
    a.add_argument("--limit", type=int, default=15, help="manual findings to print")
    a.add_argument("--fail-on-findings", action="store_true", help="exit 1 when any check fails (for CI)")
    a.set_defaults(fn=cmd_assess)

    s = sub.add_parser("serve", help="start the dashboard")
    common(s)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)

    r = sub.add_parser("rules", help="list the rules")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
