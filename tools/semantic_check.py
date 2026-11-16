#!/usr/bin/env python3
"""
semantic_check.py - compile-check every rule with Microsoft's own Kusto language service.

lint_kql.py looks for known bug patterns. This goes further: it parses and type-checks
each query exactly as the Kusto engine would, offline, with no cluster. It catches
operators and functions that do not exist, columns that do not exist, and joins on
keys missing from one side.

Two passes:
  tests       every test query: fixture tables + the lab build of the rule
              (exactly what run_tests.py sends to the engine)
  production  every production build (tools/prod_build.py), against empty tables of
              the Defender schema - so a column Defender doesn't have is an error

    npm install --prefix tools/semantic          # once
    python tools/semantic_check.py               # exit 1 on any error
    python tools/semantic_check.py --json docs/semantic.json
"""
import argparse
import copy
import glob
import json
import os
import subprocess
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import kql_testkit as tk            # noqa: E402
import run_tests as rt              # noqa: E402
from prod_build import prod_build   # noqa: E402

ANALYZER = os.path.join(HERE, "semantic", "analyze.js")

# The Defender schema without the non-standard columns kql_testkit keeps so legacy
# rules resolve: in production these are phantom columns (bug class 6).
NON_STANDARD = {"*": {"InitiatingProcessSigner"}, "DeviceRegistryEvents": {"AccountName"}}
STRICT_SCHEMA = {
    table: [c for c in cols if c[0] not in NON_STANDARD["*"] | NON_STANDARD.get(table, set())]
    for table, cols in copy.deepcopy(tk.MDE_SCHEMA).items()
}


def read(path):
    return open(path, "rb").read().decode("utf-8-sig").replace("\r\n", "\n")


def collect(scope):
    items = []
    if scope in ("all", "tests"):
        for f, rel, _, _ in rt.discover():
            case = yaml.safe_load(open(f, encoding="utf-8")) or {}
            rule = read(rt.resolve(f, case["rule"]))
            fixtures = rt.load_fixture(rt.resolve(f, case.get("fixture", "fixtures")))
            items.append({"kind": "test", "name": rel, "text": tk.build_query(rule, fixtures, tk.MDE_SCHEMA)})
    if scope in ("all", "production"):
        for folder in tk.detection_dirs():
            for rule_file in sorted(glob.glob(os.path.join(folder, "*.kql"))):
                text, _ = prod_build(read(rule_file))
                name = os.path.relpath(rule_file, os.path.join(ROOT, tk.content_root())).replace(os.sep, "/")
                items.append({"kind": "production", "name": name, "text": tk.build_query(text, {}, STRICT_SCHEMA)})
    if scope in ("all", "docs"):
        import re
        for md in sorted(glob.glob(os.path.join(ROOT, tk.content_root(), "*", "docs", "*.md"))):
            for i, q in enumerate(re.findall(r"```kql\n(.*?)```", read(md), re.S), 1):
                name = f"{os.path.relpath(md, os.path.join(ROOT, tk.content_root())).replace(os.sep, '/')} #{i}"
                items.append({"kind": "doc-query", "name": name, "text": tk.build_query(q, {}, STRICT_SCHEMA)})
    return items


def analyze(items):
    if not os.path.isdir(os.path.join(HERE, "semantic", "node_modules")):
        sys.exit("Kusto language service not installed. Run:  npm install --prefix tools/semantic")
    payload = json.dumps([{"name": i["name"], "text": i["text"]} for i in items])
    proc = subprocess.run(["node", ANALYZER], input=payload, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode:
        sys.exit(proc.stderr)
    return json.loads(proc.stdout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", choices=["all", "tests", "production", "docs"], default="all")
    ap.add_argument("--json", help="write results to this file")
    args = ap.parse_args()

    items = collect(args.scope)
    results = analyze(items)
    bad = 0
    for item, res in zip(items, results):
        errs = res["errors"]
        bad += bool(errs)
        print(f"  {'ERROR' if errs else 'clean'}  {item['kind']:<10}  {item['name']}")
        for e in errs[:8]:
            print(f"           line {e['line']}: {e['message']}  [{e['at']}]")
    print(f"\n{len(items) - bad}/{len(items)} queries compile clean (Microsoft Kusto language service)")

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([{**{"kind": i["kind"], "name": i["name"]}, "errors": r["errors"]}
                       for i, r in zip(items, results)], fh, indent=2)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### Compile check\n\n{len(items) - bad}/{len(items)} queries compile clean "
                     f"with Microsoft's Kusto language service.\n\n")
            for item, res in zip(items, results):
                for e in res["errors"]:
                    fh.write(f"- `{item['name']}` line {e['line']}: {e['message']}\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
