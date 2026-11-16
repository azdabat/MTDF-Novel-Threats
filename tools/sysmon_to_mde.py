#!/usr/bin/env python3
"""
sysmon_to_mde.py  —  convert a LIVE VM Sysmon export (from Export-SysmonWindow.ps1)
into Defender(MDE)-shaped per-table JSON.

    python3 sysmon_to_mde.py -i lsass.raw.json -o tests/fixtures/lsass_comsvcs
"""
import argparse
import json
import os

import mde_mapping


def write_tables(tables, outdir, ndjson=False):
    os.makedirs(outdir, exist_ok=True)
    for table, rows in sorted(tables.items()):
        path = os.path.join(outdir, f"{table}.{'ndjson' if ndjson else 'json'}")
        with open(path, "w", encoding="utf-8") as f:
            if ndjson:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            else:
                json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"  {table:<26} {len(rows):>6}  -> {path}")


def main():
    ap = argparse.ArgumentParser(description="Live VM Sysmon export -> MDE JSON.")
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--outdir", required=True)
    ap.add_argument("--ndjson", action="store_true")
    ap.add_argument("--provenance", action="store_true")
    ap.add_argument("--device", help="override DeviceName on every row")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = [data]

    tables, skipped = mde_mapping.convert_events(
        data, provenance=args.provenance, device_override=args.device)
    write_tables(tables, args.outdir, ndjson=args.ndjson)
    if not tables:
        print("  (no mappable events)")
    if skipped:
        print("  skipped:", ", ".join(f"EID{e}x{n}" for e, n in sorted(skipped.items(), key=lambda x: str(x[0]))))


if __name__ == "__main__":
    main()
