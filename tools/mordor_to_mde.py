#!/usr/bin/env python3
"""
mordor_to_mde.py - convert an OTRF Security-Datasets (Mordor) capture into
Microsoft Defender (MDE)-shaped per-table JSON fixtures.

Handles both OTRF record formats:
  current (2020+) : Channel / EventID / Hostname / RecordNumber,
                    Sysmon fields promoted to top-level keys
  legacy  (2019)  : log_name / event_id / computer_name / record_number,
                    Sysmon fields nested under event_data{}

Accepts .json, .zip, .tar and .tar.gz (OTRF ships all of these).

    python tools/mordor_to_mde.py -i dataset.zip -o tests/fixtures/my_case
    python tools/mordor_to_mde.py -i dataset.tar.gz -o tests/fixtures/my_case --eventid 1,12,13 --limit-per-table 2000
"""
import argparse
import io
import json
import os
import tarfile
import zipfile

import mde_mapping

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _iter_lines(fh):
    for line in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def iter_records(path):
    """Yield raw records from a .json / .zip / .tar / .tar.gz dataset.
    Archives with no JSON inside (e.g. network pcap captures) yield nothing."""
    low = path.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            name = next((n for n in z.namelist() if n.lower().endswith(".json")), None)
            if name is None:
                return
            with z.open(name) as fh:
                yield from _iter_lines(fh)
    elif low.endswith((".tar", ".tar.gz", ".tgz")):
        mode = "r:gz" if low.endswith((".gz", ".tgz")) else "r:"
        with tarfile.open(path, mode) as t:
            member = next((m for m in t.getmembers() if m.name.lower().endswith(".json")), None)
            if member is None:
                return
            yield from _iter_lines(t.extractfile(member))
    else:
        with open(path, "rb") as fh:
            head = fh.read(4096).decode("utf-8-sig", errors="replace").lstrip()
            fh.seek(0)
            if head.startswith("["):              # a JSON array (Export-SysmonWindow.ps1 capture)
                yield from json.loads(fh.read().decode("utf-8-sig"))
            else:                                 # NDJSON (OTRF datasets)
                yield from _iter_lines(fh)


def _host(value):
    if isinstance(value, dict):
        return value.get("name") or value.get("hostname")
    return value


def normalize_record(r, keep=None):
    """Raw OTRF record -> mapper event dict, or None if not a wanted Sysmon event."""
    if "EventId" in r and isinstance(r.get("EventData"), dict):   # own lab capture (Export-SysmonWindow.ps1)
        try:
            eid = int(r["EventId"])
        except (TypeError, ValueError):
            return None
        if keep is not None and eid not in keep:
            return None
        return {"EventId": eid, "Computer": r.get("Computer"), "TimeCreated": r.get("TimeCreated"),
                "RecordId": r.get("RecordId"), "EventData": r["EventData"]}
    if r.get("Channel") == SYSMON_CHANNEL:                    # current format
        eid, data = r.get("EventID"), r
        computer = r.get("Hostname") or _host(r.get("host"))
        record = r.get("RecordNumber")
    elif r.get("log_name") == SYSMON_CHANNEL:                 # legacy format
        eid, data = r.get("event_id"), (r.get("event_data") or {})
        computer = r.get("computer_name") or _host(r.get("host"))
        record = r.get("record_number")
    else:
        return None
    try:
        eid = int(eid)
    except (TypeError, ValueError):
        return None
    if keep is not None and eid not in keep:
        return None
    return {"EventId": eid, "Computer": computer, "TimeCreated": r.get("@timestamp"),
            "RecordId": record, "EventData": data}


def load_events(path, keep=None):
    return [e for e in (normalize_record(r, keep) for r in iter_records(path)) if e]


def write_tables(tables, outdir, limit=0, ndjson=False, quiet=False):
    """Write {table: rows} as <outdir>/<Table>.json. Returns total rows written."""
    os.makedirs(outdir, exist_ok=True)
    total = 0
    for table, rows in sorted(tables.items()):
        if limit and len(rows) > limit:
            rows = rows[:limit]
        path = os.path.join(outdir, f"{table}.{'ndjson' if ndjson else 'json'}")
        with open(path, "w", encoding="utf-8") as f:
            if ndjson:
                for row in rows:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            else:
                json.dump(rows, f, ensure_ascii=False, indent=2)
        total += len(rows)
        if not quiet:
            print(f"  {table:<26} {len(rows):>6}  -> {path}")
    return total


def main():
    ap = argparse.ArgumentParser(description="OTRF / Mordor dataset -> MDE-shaped fixture JSON.")
    ap.add_argument("-i", "--input", required=True, help=".json, .zip, .tar or .tar.gz")
    ap.add_argument("-o", "--outdir", required=True)
    ap.add_argument("--eventid", help="comma list of Sysmon EventIDs to keep (default: all mapped)")
    ap.add_argument("--limit-per-table", type=int, default=0, help="cap rows per table (0 = no cap)")
    ap.add_argument("--ndjson", action="store_true")
    ap.add_argument("--provenance", action="store_true", help="keep _SysmonEventId/_SysmonRecordId")
    ap.add_argument("--device", help="override DeviceName on every row")
    args = ap.parse_args()

    keep = {int(x) for x in args.eventid.split(",")} if args.eventid else None
    events = load_events(args.input, keep)
    tables, skipped = mde_mapping.convert_events(
        events, provenance=args.provenance, device_override=args.device)
    write_tables(tables, args.outdir, limit=args.limit_per_table, ndjson=args.ndjson)
    print(f"  consumed {len(events)} sysmon events")
    if skipped:
        print("  skipped:", ", ".join(f"EID{e}x{n}" for e, n in sorted(skipped.items(), key=lambda x: str(x[0]))))


if __name__ == "__main__":
    main()
