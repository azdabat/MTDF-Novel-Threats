#!/usr/bin/env python3
"""
prod_build.py - turn the lab builds in detections/ back into production rules.

Every lab change is marked on its line as  // LAB: production uses <value>.
This restores <value> on that line and removes the marker. Nothing else changes,
so the production rule carries every fix the tests proved.

    python tools/prod_build.py                 # writes production/<SourceRule>.kql for every detection
    python tools/prod_build.py --out C:\\temp\\rules
"""
import argparse
import glob
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARK = re.compile(r"\s*//\s*LAB: production uses (\S+)")


def prod_build(text):
    out, restored = [], []
    for line in text.split("\n"):
        m = MARK.search(line)
        if m:
            value = m.group(1)
            line = MARK.sub("", line).replace("3650d", value, 1)
            restored.append(value)
        out.append(line)
    return "\n".join(out), restored


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "production"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    n = 0
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import kql_testkit as tk
    for folder in tk.detection_dirs():
        meta_file = os.path.join(folder, "detection.yml")
        meta = yaml.safe_load(open(meta_file, encoding="utf-8")) or {}
        rules = glob.glob(os.path.join(folder, "*.kql"))
        if not rules:
            continue
        raw = open(rules[0], "rb").read().decode("utf-8-sig").replace("\r\n", "\n")
        text, restored = prod_build(raw)
        if "3650d" in re.sub(r"//[^\n]*", "", text):
            print(f"  WARNING {os.path.basename(rules[0])}: a 3650d window has no LAB marker - check it by hand")
        name = (meta.get("source_rule") or os.path.splitext(os.path.basename(rules[0]))[0]) + ".kql"
        with open(os.path.join(args.out, name), "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"  {name:<62} lookbacks restored: {', '.join(restored) or '-'}")
        n += 1
    print(f"\n{n} production rules written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
