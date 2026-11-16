#!/usr/bin/env python3
"""
add_detection.py - add a rule to a threat, as a tested detection.

    python tools/add_detection.py --threat nodejs-runtime-abuse --rule NodeJS_Loader_Execution.kql \
        --name nodejs_loader_execution --tactic execution --technique T1059.007 \
        --architecture "Composite sensor" --title "Node.js Loader Execution" \
        --minimum-truth "A Node.js runtime runs from, or runs a script from, a user-writable location" \
        --capture node_lab_v1 --catches "copied node.exe in %TEMP% running update.js"

Writes threats/<threat>/detections/<name>/ with the lab build of the rule and detection.yml.
If the capture is already in telemetry/, the test and its fixtures are built straight away;
otherwise they are built when tools/add_capture.py registers it.
"""
import argparse
import os
import sys

import threatkit as tk


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threat", required=True)
    ap.add_argument("--rule", required=True, help="the production .kql")
    ap.add_argument("--name", required=True, help="folder name, lowercase_with_underscores")
    ap.add_argument("--tactic", required=True, choices=tk.at.SLUGS)
    ap.add_argument("--technique", required=True, help="comma list, e.g. T1059.007")
    ap.add_argument("--architecture", required=True, choices=tk.ARCHITECTURES)
    ap.add_argument("--title", required=True)
    ap.add_argument("--minimum-truth", required=True)
    ap.add_argument("--reinforcement", default="")
    ap.add_argument("--capture", help="telemetry id the test runs against")
    ap.add_argument("--catches", default="", help="what the rule must catch in that capture")
    ap.add_argument("--lookback", default="1d", help="production lookback")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    tdir = os.path.join(tk.THREATS, args.threat)
    if not os.path.isfile(os.path.join(tdir, "threat.yml")):
        sys.exit(f"no threat at threats/{args.threat} (tools/new_threat.py creates one)")
    ddir = os.path.join(tdir, "detections", args.name)
    if os.path.exists(ddir) and not args.force:
        sys.exit(f"{ddir} exists (use --force to replace)")
    os.makedirs(ddir, exist_ok=True)
    rule_path, notes = tk.write_rule(args.rule, ddir)
    for n in notes:
        print(f"  LAB {n}")
    text = open(rule_path, encoding="utf-8").read()
    import re
    meta = {
        "title": args.title, "author": "Ala Dabat", "architecture": args.architecture, "tactic": args.tactic,
        "techniques": [t.strip() for t in args.technique.split(",") if t.strip()],
        "minimum_truth": args.minimum_truth, "reinforcement": args.reinforcement,
        "data_sources": sorted(set(re.findall(r"\b(Device\w+Events|DeviceFileCertificateInfo)\b", text))),
        "platforms": ["Microsoft Defender XDR Advanced Hunting", "Microsoft Sentinel (MDE connector)"],
        "production_lookback": args.lookback,
        "source_rule": os.path.splitext(os.path.basename(args.rule))[0],
        "tests": [],
    }
    if args.capture:
        meta["tests"].append({"capture": args.capture, "catches": args.catches, "expect": {"must_fire": True}})
    tk.dump_yaml(os.path.join(ddir, "detection.yml"), meta,
                 header="# Detection metadata - source of truth for the threat README and the tests.")
    caps = tk.captures(tdir)
    if args.capture and args.capture in caps:
        for det, rows in tk.materialize_tests(ddir, args.capture, caps[args.capture][0]):
            print(f"  test built from capture {args.capture}: {rows} fixture rows")
    elif args.capture:
        print(f"  capture {args.capture} not in telemetry/ yet - the test is built when add_capture.py registers it")
    print(f"created threats/{args.threat}/detections/{args.name}/  - add it to attack_surface in threat.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
