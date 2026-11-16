#!/usr/bin/env python3
"""
hunt_all.py - run every rule, unchanged, against the real tables in your database.

This is "tenant mode": the rules hunt over everything loaded (your own lab captures
plus the Empire / Covenant / OTRF telemetry from tenant_setup + ingest_to_adx), exactly
as they would in Defender. It complements run_tests.py, which proves each rule against
the one attack it must catch.

    python tools/hunt_all.py                  # summary: alerts per rule
    python tools/hunt_all.py -k psexec --show # also print the alert rows
"""
import argparse
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import kql_testkit as tk        # noqa: E402

SHOW_COLS = ("Timestamp", "FirstSeen", "DeviceName", "Severity", "RiskScore", "RiskLevel",
             "PersistenceClass", "TaskActionCategory", "FileName", "Child", "ProcessCommandLine")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", "--filter", default="")
    ap.add_argument("--show", action="store_true", help="print the alert rows")
    ap.add_argument("--cluster", default=os.environ.get("ADX_CLUSTER", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("ADX_DB", "NetDefaultDB"))
    args = ap.parse_args()

    rules = sorted(p for d in tk.detection_dirs() for p in glob.glob(os.path.join(d, "*.kql")))
    errors = 0
    print(f"{'detection':<48} {'alerts':>6}  devices")
    for path in rules:
        name = os.path.basename(os.path.dirname(path))
        if args.filter and args.filter not in path.replace(os.sep, "/"):
            continue
        text = open(path, "rb").read().decode("utf-8-sig").replace("\r\n", "\n")
        payload, err = tk._post(args.cluster, args.db, text, timeout=180)
        if payload is None:
            errors += 1
            print(f"{name:<48}  ERROR  {(err or '')[:150]}")
            continue
        rows = tk._rows_from_v1(payload)
        devices = sorted({str(r.get("DeviceName")) for r in rows if r.get("DeviceName")})
        print(f"{name:<48} {len(rows):>6}  {', '.join(devices[:4])}")
        if args.show:
            for r in rows[:20]:
                print("      " + " | ".join(f"{c}={str(r[c])[:90]}" for c in SHOW_COLS if r.get(c) not in (None, "")))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
