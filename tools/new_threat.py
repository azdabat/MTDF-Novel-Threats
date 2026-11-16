#!/usr/bin/env python3
"""
new_threat.py - start a new threat folder from threats/_template.

    python tools/new_threat.py --slug silverfox-byovd --name "SilverFox / ValleyRAT BYOVD" \
        --type campaign --status active --first-seen 2024 --platforms Windows

Then fill threats/<slug>/threat.yml (summary, threat model, attack-surface matrix) and the
three docs, write the emulation, capture telemetry, and add detections.
"""
import argparse
import os
import shutil
import sys

import threatkit as tk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True, help="lowercase-with-hyphens, e.g. etherrat-react2shell")
    ap.add_argument("--name", required=True)
    ap.add_argument("--type", required=True, choices=tk.TYPES)
    ap.add_argument("--status", default="emerging", choices=tk.STATUSES)
    ap.add_argument("--first-seen", default="")
    ap.add_argument("--platforms", default="Windows", help="comma list")
    ap.add_argument("--cve", default="", help="comma list, zero-days")
    args = ap.parse_args()

    if not tk.SLUG_RX.match(args.slug):
        sys.exit("slug must be lowercase words joined by hyphens")
    dest = os.path.join(tk.THREATS, args.slug)
    if os.path.exists(dest):
        sys.exit(f"{dest} already exists")
    shutil.copytree(os.path.join(tk.THREATS, "_template"), dest)
    meta_path = os.path.join(dest, "threat.yml")
    meta = tk.load_yaml(meta_path)
    meta.update({"name": args.name, "slug": args.slug, "type": args.type, "status": args.status,
                 "first_seen": args.first_seen,
                 "platforms": [p.strip() for p in args.platforms.split(",") if p.strip()],
                 "cves": [c.strip() for c in args.cve.split(",") if c.strip()]})
    tk.dump_yaml(meta_path, meta, header="# Threat metadata and attack-surface matrix - see THREAT_FORMAT.md")
    print(f"created threats/{args.slug}/")
    for root, _, files in os.walk(dest):
        for f in sorted(files):
            print("  " + os.path.relpath(os.path.join(root, f), dest).replace(os.sep, "/"))
    print("\nnext: fill threat.yml + docs/, write emulation/, capture telemetry, then tools/add_detection.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
