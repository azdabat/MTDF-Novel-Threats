#!/usr/bin/env python3
"""
bulk_convert.py - convert a whole DIRECTORY of OTRF datasets into fixtures.

Walks a folder (e.g. a sparse clone of OTRF Security-Datasets) and writes one
fixture folder per dataset under tests/fixtures/. Reads .zip/.tar/.tar.gz
archives directly - nothing needs unzipping first.

    python tools/bulk_convert.py ../Security-Datasets/datasets/atomic/windows
    python tools/bulk_convert.py <dir> --eventid 1,12,13 --limit-per-table 2000
    python tools/bulk_convert.py <dir> --filter "*"          # not just empire_*

Keep --limit-per-table generous: a low cap can cut the single event a rule
needs (e.g. one service ImagePath write among ~1,000 registry events).
"""
import argparse
import fnmatch
import os
import sys

import mde_mapping
import mordor_to_mde as m2m

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".json")


def dataset_stem(fname):
    """empire_x_2020-09-21175806.json -> empire_x  (drop extension and capture timestamp)."""
    base = fname
    for ext in (".tar.gz", ".tgz", ".tar", ".zip", ".json"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    head, _, tail = base.rpartition("_")
    if head and tail[:4].isdigit() and "-" in tail:
        base = head
    return base


def find_datasets(root, pattern):
    hits = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.lower().endswith(DATASET_EXT) and fnmatch.fnmatch(f.lower(), pattern.lower()):
                hits.append(os.path.join(dirpath, f))
    return sorted(hits)


def main():
    ap = argparse.ArgumentParser(description="Convert a directory of OTRF datasets into fixtures.")
    ap.add_argument("directory", help="folder to walk for datasets")
    ap.add_argument("--filter", default="empire_*", help="filename glob (default: empire_*)")
    ap.add_argument("--out", default="tests/fixtures", help="fixtures root")
    ap.add_argument("--eventid", help="comma list of Sysmon EventIDs to keep")
    ap.add_argument("--limit-per-table", type=int, default=2000)
    ap.add_argument("--provenance", action="store_true")
    args = ap.parse_args()

    keep = {int(x) for x in args.eventid.split(",")} if args.eventid else None
    out_root = args.out if os.path.isabs(args.out) else os.path.join(ROOT, args.out)
    pattern = args.filter if "*" in args.filter else args.filter + "*"

    datasets = find_datasets(args.directory, pattern)
    if not datasets:
        print(f"no datasets matching '{args.filter}' under {args.directory}", file=sys.stderr)
        return 1

    print(f"found {len(datasets)} datasets\n")
    for path in datasets:
        stem = dataset_stem(os.path.basename(path))
        try:
            events = m2m.load_events(path, keep)
            tables, _ = mde_mapping.convert_events(events, provenance=args.provenance)
            if not tables:
                print(f"  SKIP {stem:<60} (no host telemetry / network capture)")
                continue
            rows = m2m.write_tables(tables, os.path.join(out_root, stem),
                                    limit=args.limit_per_table, quiet=True)
            print(f"  OK   {stem:<60} {len(events):>6} events -> {rows:>5} rows")
        except Exception as e:  # keep going; one bad archive shouldn't stop the batch
            print(f"  ERR  {stem:<60} {e}")
    print(f"\nfixtures written under {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
