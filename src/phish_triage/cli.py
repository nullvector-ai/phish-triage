"""phish-triage CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import format_text, triage


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="phish-triage", description="Triage .eml files for phishing.")
    p.add_argument("files", nargs="*", help=".eml files (default: read stdin)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--no-llm", action="store_true", help="skip the LLM even if configured")
    args = p.parse_args(argv)

    sources = [(f, Path(f).read_bytes()) for f in args.files] or [("<stdin>", sys.stdin.buffer.read())]
    worst = 0
    results = []
    for name, raw in sources:
        r = triage(raw, use_llm=not args.no_llm)
        r["file"] = name
        results.append(r)
        worst = max(worst, {"likely_benign": 0, "suspicious": 1, "phishing": 2}[r["rule_verdict"]])
    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(f"== {r['file']} ==\n{format_text(r)}" for r in results))
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
