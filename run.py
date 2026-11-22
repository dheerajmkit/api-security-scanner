#!/usr/bin/env python3
"""Audit an OpenAPI specification for API security gaps.

Usage:
    python3 run.py <spec.json> [--json]

Exit codes: 2 = usage error / unreadable spec,
            1 = at least one high finding,
            0 = no high findings.
"""

import argparse
import sys

from api.loader import load_spec
from api.checks import check_spec
from api.report import summarize, render_text, render_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", help="OpenAPI JSON file")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    args = parser.parse_args(argv)

    try:
        spec = load_spec(args.spec)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load spec: {exc}", file=sys.stderr)
        return 2

    findings = check_spec(spec)

    if args.json:
        print(render_json(args.spec, findings))
    else:
        print(render_text(args.spec, findings))

    counts = summarize(findings)
    return 1 if counts["HIGH"] or counts["CRITICAL"] else 0


if __name__ == "__main__":
    sys.exit(main())
