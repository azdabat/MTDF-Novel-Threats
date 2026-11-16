#!/usr/bin/env python3
"""
tenant_setup.py - make the Kustainer database look like a Defender tenant.

Every Device* table gets the Defender columns the rules use (kql_testkit.MDE_SCHEMA),
so any rule pasted into the ADX web UI resolves exactly as it would in Defender XDR.
Safe to run any number of times; rows already in the tables are kept.

  table missing            -> created with the Defender schema
  table missing columns    -> columns added (.create-merge); old rows get empty values
  column with a wrong type -> table rebuilt: old one renamed <Table>_old_<n>, new one
                              created, every row copied across (matched by column name)
  table empty, backup full -> rows restored from the newest <Table>_old_<n> backup

    python tools/tenant_setup.py
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import kql_testkit as tk                     # noqa: E402
from ingest_to_adx import mgmt               # noqa: E402


def columns_csl(cols):
    return ", ".join(f"{c}:{t}" for c, t in cols)


def count(cluster, db, query):
    payload, _ = tk._post(cluster, db, query)
    rows = tk._rows_from_v1(payload) if payload else []
    return rows


def copy_rows(cluster, db, src, table):
    target = tk.table_schema(cluster, db, table)
    ok, err = mgmt(cluster, db, f".append {table} <| {src} | {tk.conform(target)}")
    return ok, err


def restore_if_empty(cluster, db, table):
    """If a rebuild was interrupted, the new table is empty and the rows sit in a backup."""
    rows = count(cluster, db, f"{table} | count")
    if not rows or rows[0]["Count"] > 0:
        return None
    backups = count(cluster, db, f"union isfuzzy=true withsource=Src {table}_old_* | summarize N = count() by Src")
    backups = sorted((r for r in backups if r.get("N")), key=lambda r: r["Src"])
    if not backups:
        return None
    src = backups[-1]["Src"]
    ok, err = copy_rows(cluster, db, src, table)
    return f"restored {backups[-1]['N']} rows from {src}" if ok else f"FAILED restoring from {src}: {err}"


def setup_table(cluster, db, table, wanted):
    have = tk.table_schema(cluster, db, table)
    if have is None:
        ok, err = mgmt(cluster, db, f".create table {table} ({columns_csl(wanted)})")
        return "created" if ok else f"FAILED: {err}"
    have_d = dict(have)

    conflicts = [(c, have_d[c], t) for c, t in wanted if c in have_d and have_d[c] != t]
    if not conflicts:
        missing = [(c, t) for c, t in wanted if c not in have_d]
        status = "ok (already Defender-shaped)"
        if missing:
            ok, err = mgmt(cluster, db, f".create-merge table {table} ({columns_csl(wanted)})")
            if not ok:
                return f"FAILED: {err}"
            status = (f"added {len(missing)} column(s): {', '.join(c for c, _ in missing[:6])}"
                      f"{' ...' if len(missing) > 6 else ''}")
        restored = restore_if_empty(cluster, db, table)
        return f"{status}; {restored}" if restored else status

    # A column exists with another type: rebuild and copy every row across by name.
    old = f"{table}_old_{int(time.time())}"
    target = wanted + [(c, t) for c, t in have if c not in dict(wanted)]
    for csl in (f".rename table {table} to {old}", f".create table {table} ({columns_csl(target)})"):
        ok, err = mgmt(cluster, db, csl)
        if not ok:
            return f"FAILED during rebuild: {err}"
    ok, err = copy_rows(cluster, db, old, table)
    if not ok:
        return f"FAILED copying rows from {old} (they are safe there): {err}"
    fixed = ", ".join(f"{c} {a}->{b}" for c, a, b in conflicts[:4])
    return f"rebuilt (type fixed: {fixed}); rows copied, original kept as {old}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", default=os.environ.get("ADX_CLUSTER", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("ADX_DB", "NetDefaultDB"))
    args = ap.parse_args()
    failed = 0
    for table, cols in tk.MDE_SCHEMA.items():
        status = setup_table(args.cluster, args.db, table, cols)
        failed += "FAILED" in status
        print(f"  {table:<28} {status}")
    print("\nDatabase is Defender-shaped." if not failed else "\nSome tables failed - send this output to Claude.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
