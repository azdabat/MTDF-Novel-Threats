#!/usr/bin/env python3
"""
promote.py - promote experimental tests that passed the last CI run to stable.

A stable test fails the build when it regresses; an experimental one only reports.
Promotion is a deliberate step: review the run, then promote.

    git pull                                  # brings in docs/results.json from CI
    python tools/promote.py                   # show what would be promoted
    python tools/promote.py --apply           # rewrite maturity: experimental -> stable
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import kql_testkit as tk  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(ROOT, "docs", "results.json"))
    ap.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    args = ap.parse_args()
    if not os.path.exists(args.results):
        print(f"{args.results} not found - run 'git pull' after a CI run first")
        return 1
    data = json.load(open(args.results, encoding="utf-8"))
    print(f"results from {data.get('run_utc', '?')}")

    promote, stay = [], []
    for t in data["tests"]:
        if t["maturity"] != "experimental":
            continue
        (promote if t["status"] == "pass" and not t.get("known_issue") else stay).append(t)

    for t in promote:
        path = os.path.join(ROOT, tk.content_root(), *t["test"].split("/"))
        print(f"  PROMOTE  {t['test']}  ({t['rows']} rows)")
        if args.apply:
            text = open(path, encoding="utf-8").read()
            text = re.sub(r"^maturity:\s*experimental\s*$", "maturity: stable", text, count=1, flags=re.M)
            open(path, "w", encoding="utf-8").write(text)
    for t in stay:
        why = t.get("known_issue") or "; ".join(t.get("fails", []))[:140]
        print(f"  keep     {t['test']}  [{t['status']}] {why}")

    print(f"\n{len(promote)} to promote, {len(stay)} stay experimental"
          + ("" if args.apply or not promote else "  - re-run with --apply to write"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
