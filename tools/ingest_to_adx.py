#!/usr/bin/env python3
"""
ingest_to_adx.py  —  load converted MDE fixtures into ADX tables, the right way.

YOU PROBABLY DON'T NEED THIS. For testing rules, run_tests.py shadows the fixture
data straight into the query (no ingestion). Use this ONLY if you want the
telemetry sitting in your ADX tables for free-form interactive hunting.

What it does right (vs. ingesting one record at a time):
  - converts first, so rows land in the correct Device* tables with real MDE
    columns your rules actually query (not a single raw-text blob);
  - sends ONE `.set-or-append` per table (chunked), not one HTTP POST per record.

    # first convert a dataset to a fixture (bulk_convert.py or mordor_to_mde.py), then:
    python3 tools/ingest_to_adx.py tests/fixtures/registry_persistence_taskcache
    python3 tools/ingest_to_adx.py tests/fixtures --recurse        # all fixtures
    python3 tools/ingest_to_adx.py tests/fixtures/foo --fresh      # drop+recreate tables first
    python3 tools/ingest_to_adx.py --all-detections                # every fixture in detections/, de-duplicated
"""
import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.request

import kql_testkit as tk

CHUNK = 2000  # rows per .set-or-append; keeps each request a sane size


def mgmt(cluster, db, csl, timeout=180):
    """POST a management command to the ADX control endpoint."""
    url = cluster.rstrip("/") + "/v1/rest/mgmt"
    data = json.dumps({"db": db, "csl": csl}).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True, None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            msg = (json.loads(body).get("error", {}) or {}).get("@message") or body
        except json.JSONDecodeError:
            msg = body
        return False, msg
    except urllib.error.URLError as e:
        return False, f"connection error: {e} (is kustainer at {cluster}?)"


def ingest_table(cluster, db, table, rows, fresh):
    if table not in tk.MDE_SCHEMA:
        return 0, f"no schema for {table} (add it to kql_testkit.MDE_SCHEMA)"
    if fresh:
        mgmt(cluster, db, f".drop table {table} ifexists")  # best-effort
    target = tk.table_schema(cluster, db, table)
    if target is None:
        cols = ", ".join(f"{c}:{t}" for c, t in tk.MDE_SCHEMA[table])
        ok, err = mgmt(cluster, db, f".create table {table} ({cols})")
        if not ok:
            return 0, err
        target = tk.MDE_SCHEMA[table]
    # Columns are matched by NAME, so an older table with another column order or
    # extra columns still takes the rows; anything it lacks is left empty.
    shape = tk.conform(target)
    done = 0
    for i in range(0, len(rows), CHUNK):
        chunk = rows[i:i + CHUNK]
        csl = f".append {table} <|\n{tk.datatable_expr(table, chunk, tk.MDE_SCHEMA)}\n| {shape}"
        ok, err = mgmt(cluster, db, csl)
        if not ok:
            return done, err
        done += len(chunk)
    return done, None


def already_loaded(cluster, db, table, rows):
    """Rows already in the table inside this telemetry's time range (so a re-run never duplicates)."""
    times = sorted(str(r["Timestamp"]) for r in rows if r.get("Timestamp"))
    if not times:
        return 0
    payload, _ = tk._post(cluster, db, f"{table} | where Timestamp between (datetime({times[0]}) .. "
                                       f"datetime({times[-1]})) | count")
    return tk._rows_from_v1(payload)[0]["Count"] if payload else 0


def load_all(args):
    root = os.path.join(tk.REPO_ROOT, tk.content_root())
    dirs = sorted(d for d in glob.glob(os.path.join(root, "**", "fixtures*"), recursive=True) if os.path.isdir(d))
    tables, seen = {}, set()
    for d in dirs:
        for f in glob.glob(os.path.join(d, "*.json")):
            table = os.path.splitext(os.path.basename(f))[0]
            with open(f, encoding="utf-8") as fh:
                for row in json.load(fh):
                    key = (table, json.dumps(row, sort_keys=True))
                    if key not in seen:
                        seen.add(key)
                        tables.setdefault(table, []).append(row)
    print(f"{len(dirs)} fixture folders -> {sum(map(len, tables.values()))} unique rows")
    grand, failed = 0, 0
    for table in sorted(tables):
        present = 0 if args.fresh else already_loaded(args.cluster, args.db, table, tables[table])
        if present:
            print(f"  {table:<26} already loaded ({present} rows in that time range) - skipped")
            continue
        n, err = ingest_table(args.cluster, args.db, table, tables[table], args.fresh)
        grand += n
        if err:
            failed += 1
            print(f"  {table:<26} FAILED: {err[:300]}")
        else:
            print(f"  {table:<26} {n} rows -> {args.db}")
    print(f"\ningested {grand} rows into {args.db}")
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture_dir", nargs="?", help="a fixture dir (Device*.json), or a parent with --recurse")
    ap.add_argument("--all-detections", action="store_true",
                    help="load every fixture under detections/ once (the same capture used by several tests is de-duplicated)")
    ap.add_argument("--cluster", default=os.environ.get("ADX_CLUSTER", "http://localhost:8080"))
    ap.add_argument("--db", default=os.environ.get("ADX_DB", "NetDefaultDB"))
    ap.add_argument("--recurse", action="store_true", help="treat dir as a parent of many fixture dirs")
    ap.add_argument("--fresh", action="store_true", help="drop each table before loading (destructive)")
    args = ap.parse_args()

    if args.all_detections:
        return load_all(args)
    if not args.fixture_dir:
        ap.error("give a fixture_dir or --all-detections")
    base = os.path.normpath(args.fixture_dir)
    if args.recurse:
        dirs = sorted(d for d in glob.glob(os.path.join(base, "*")) if os.path.isdir(d))
    else:
        dirs = [base]

    grand = 0
    for d in dirs:
        files = sorted(os.path.normpath(p) for p in glob.glob(os.path.join(d, "*.json")))
        if not files:
            continue
        print(f"\n{os.path.basename(d)}:")
        for f in files:
            table = os.path.splitext(os.path.basename(f))[0]
            with open(f, encoding="utf-8") as fh:
                rows = json.load(fh)
            if not rows:
                print(f"  {table:<26} 0 rows (skip)")
                continue
            n, err = ingest_table(args.cluster, args.db, table, rows, args.fresh)
            if err:
                print(f"  {table:<26} FAILED: {err}")
                if "schema" in err.lower() and "match" in err.lower():
                    print(f"       -> table exists with a different schema; re-run with --fresh, "
                          f"or point --db at an empty database.")
            else:
                print(f"  {table:<26} {n} rows -> ADX")
                grand += n
    print(f"\ningested {grand} rows total into {args.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
