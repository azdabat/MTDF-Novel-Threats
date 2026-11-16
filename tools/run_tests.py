#!/usr/bin/env python3
"""
run_tests.py - run every detection against its fixture and report the result.

Layout (one folder per detection, grouped by ATT&CK tactic):

    detections/<tactic>/<detection>/
        <Rule>.kql
        test.yml                 any *.yml in the folder is a test case
        fixtures/<Table>.json    MDE-shaped telemetry

Paths inside a test .yml (rule:, fixture:) are relative to that .yml's folder.

Maturity (set per test with `maturity:`; default stable):
    stable        a failure fails the build
    experimental  a failure is reported but does not fail the build (new or unproven tests)
A `known_issue:` marks a documented defect: its failure is reported as KNOWN, never blocking.
An engine that cannot be reached always fails the build, whatever the maturity.

    python tools/run_tests.py                            # every test
    python tools/run_tests.py -k persistence             # one tactic
    python tools/run_tests.py -k taskcache               # one detection
    python tools/run_tests.py -k taskcache --out q.kql   # write the self-contained KQL to paste into ADX
    python tools/run_tests.py --json docs/results.json   # also save machine-readable results
"""
import argparse
import datetime
import glob
import json
import os
import sys

import yaml

import kql_testkit as tk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve(case_file, rel):
    """Path from a test .yml: relative to its own folder first, then the repo root."""
    rel = rel.replace("/", os.sep)
    local = os.path.normpath(os.path.join(os.path.dirname(case_file), rel))
    return local if os.path.exists(local) else os.path.normpath(os.path.join(ROOT, rel))


def load_fixture(folder):
    fixtures = {}
    for f in sorted(glob.glob(os.path.join(folder, "*.json"))):
        table = os.path.splitext(os.path.basename(f))[0]
        with open(f, encoding="utf-8") as fh:
            fixtures[table] = json.load(fh)
    return fixtures


def discover(root_rel=None):
    """[(case_file, '<group>/.../<detection>/test.yml', group, detection)]
    group is the tactic (detections/<tactic>/<detection>/) or the threat
    (threats/<threat>/detections/<detection>/)."""
    root_rel = root_rel or tk.content_root()
    base = os.path.join(ROOT, root_rel)
    files = glob.glob(os.path.join(base, "**", "test*.yml"), recursive=True)
    out = []
    for f in sorted(files):
        parts = os.path.relpath(f, base).split(os.sep)
        if any(p.startswith("fixtures") or p == "_template" for p in parts):
            continue
        if not os.path.exists(os.path.join(os.path.dirname(f), "detection.yml")):
            continue
        group = parts[0] if len(parts) >= 3 else "unsorted"
        detection = os.path.basename(os.path.dirname(f))
        out.append((f, "/".join(parts), group, detection))
    return out


def write_step_summary(results, counts):
    """Markdown table on the GitHub Actions run page (no-op outside Actions)."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    icon = {"pass": "✅", "fail": "❌", "error": "💥", "known": "⚠️"}
    lines = ["## Detection test results", "",
             f"**{counts['pass']} passed** · {counts['fail']} failed · {counts['error']} errors · "
             f"{counts['known']} known issues · {counts['blocking']} blocking", "",
             "| | Test | Maturity | Rows | Detail |", "|---|---|---|---|---|"]
    for r in results:
        detail = "; ".join(r["fails"])[:300].replace("|", "/") or r.get("known_issue", "")[:120]
        lines.append(f"| {icon[r['status']]} | `{r['test']}` | {r['maturity']} | {r['rows']} | {detail} |")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", "--filter", default="", help="substring filter on the test path (tactic/detection/file)")
    ap.add_argument("--cluster", default=os.environ.get("ADX_CLUSTER", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("ADX_DB", "NetDefaultDB"))
    ap.add_argument("--print", dest="print_only", action="store_true", help="print the self-contained KQL")
    ap.add_argument("--out", help="write the self-contained KQL for ONE test to this file")
    ap.add_argument("--json", help="write machine-readable results here (read by build_docs.py / promote.py)")
    ap.add_argument("--root", default=None, help="content root (default: threats/ if present, else detections/)")
    args = ap.parse_args()

    cases = discover(args.root)
    if args.filter:
        cases = [c for c in cases if args.filter.lower() in c[1].lower()]
    if not cases:
        if args.filter:
            print("no matching tests")
            return 1
        print("no tests yet (no capture registered) - nothing to run")
        if args.json:
            os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump({"run_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                           "pass": 0, "fail": 0, "error": 0, "known": 0, "blocking": 0, "tests": []}, fh, indent=1)
        return 0
    if args.out and len(cases) != 1:
        print(f"--out needs exactly one test; {len(cases)} matched. Narrow it with -k.")
        return 1

    results = []
    for case_file, rel, tactic, detection in cases:
        with open(case_file, encoding="utf-8") as fh:
            case = yaml.safe_load(fh)
        name = case.get("name", rel)
        with open(resolve(case_file, case["rule"]), encoding="utf-8-sig") as fh:
            rule_text = fh.read()
        fixtures = load_fixture(resolve(case_file, case.get("fixture", "fixtures")))

        if args.print_only or args.out:
            query = tk.build_query(rule_text, fixtures, tk.MDE_SCHEMA)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(query)
                print(f"wrote {args.out}  ({len(query.splitlines())} lines) - open it, select all, paste into ADX, Run")
            else:
                print(f"\n// ===== {name} =====\n{query}")
            continue

        maturity = str(case.get("maturity", "stable")).lower()
        known = case.get("known_issue") or ""
        rows, meta, infra = [], {}, False
        try:
            rows, meta = tk.run_rule(rule_text, fixtures, cluster=args.cluster, db=args.db)
            fails = tk.evaluate(rows, case.get("expect", {}))
            status = "fail" if fails else "pass"
        except Exception as e:
            msg = str(e)
            infra = msg.startswith("connection error")
            fails, status = [f"execution error: {msg}"], "error"
        if status in ("fail", "error") and known and not infra:
            status = "known"
        blocking = status in ("fail", "error") and (maturity == "stable" or infra)

        tag = {"pass": "PASS ", "fail": "FAIL ", "error": "ERROR", "known": "KNOWN"}[status]
        exp = "" if maturity == "stable" else f" [{maturity}]"
        print(f"{tag} [{tactic}] {name}  ({len(rows)} rows){exp}")
        for f in fails if status in ("fail", "error") else []:
            print(f"        - {f[:400]}")
        if status == "known":
            print(f"        known issue: {known}")
        if status == "pass" and known:
            print("        known_issue no longer reproduces - remove the marker")
        if meta.get("healed_columns"):
            print(f"        auto-added columns: {', '.join(meta['healed_columns'])}")

        results.append({
            "test": rel, "name": name, "tactic": tactic, "detection": detection,
            "status": status, "maturity": maturity, "blocking": blocking, "rows": len(rows),
            "fails": fails if status != "pass" else [], "known_issue": known,
            "technique": str(case.get("technique", "")), "source": str(case.get("source", "")),
            "catches": str(case.get("catches", "")), "healed_columns": meta.get("healed_columns", []),
        })

    if args.print_only or args.out:
        return 0

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "fail", "error", "known")}
    counts["blocking"] = sum(1 for r in results if r["blocking"])
    print(f"\n{counts['pass']} passed, {counts['fail']} failed, {counts['error']} errors, "
          f"{counts['known']} known issues  |  {counts['blocking']} blocking")
    write_step_summary(results, counts)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"run_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                       "engine": "Kustainer (Azure Data Explorer emulator)", **counts, "tests": results}, fh, indent=1)
        print(f"results written to {args.json}")
    return 1 if counts["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
