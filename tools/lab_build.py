#!/usr/bin/env python3
"""
lab_build.py - make the lab-test copy of a production rule.

OTRF captures are from 2019-2020, so a production lookback such as 7d or 14d
filters out every row. This widens ONLY the time windows that feed ago(...):

  let lookback = 7d;  ...  ago(lookback)     ->  let lookback = 3650d;  // LAB: production uses 7d
  ago(30d)                                    ->  ago(3650d)              // LAB: production uses 30d

Correlation windows that are not used inside ago() (e.g. TimeWindow = 2m, BinSize = 15m)
are left exactly as they are, so the detection logic is unchanged.

    python tools/lab_build.py rule.kql -o detections/<tactic>/<name>/rule.kql
"""
import argparse
import re
import sys

import lint_kql as L

LAB = "3650d"
DUR = r"\d+(?:\.\d+)?\s*(?:d|h|m|s|ms|tick|day|days|hour|hours|minute|minutes)"


def lab_build(text):
    src = L.Source(text)
    code = src.code
    edits, notes = [], []
    # identifiers used directly inside ago(...)
    used = set(re.findall(r"\bago\s*\(\s*(\w+)\s*\)", code))
    for name in sorted(used):
        m = re.search(rf"\blet\s+{name}\s*=\s*({DUR})\s*;", code)
        if m and m.group(1).replace(" ", "") != LAB and not re.fullmatch(r"\d+(?:\.\d+)?", m.group(1).strip()):
            a, b = m.span(1)
            edits.append((a, b, LAB))
            eol = code.find("\n", m.end())
            eol = len(code) if eol == -1 else eol
            edits.append((eol, eol, f"   // LAB: production uses {m.group(1).strip()}"))
            notes.append(f"let {name}: {m.group(1).strip()} -> {LAB}")
    # literal durations inside ago(...)
    for m in re.finditer(rf"\bago\s*\(\s*({DUR})\s*\)", code):
        if m.group(1).replace(" ", "") == LAB:
            continue
        a, b = m.span(1)
        edits.append((a, b, LAB))
        notes.append(f"ago({m.group(1).strip()}) -> ago({LAB})")
    for a, b, r in sorted(edits, key=lambda e: e[0], reverse=True):
        text = text[:a] + r + text[b:]
    return text, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rule")
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()
    raw = open(args.rule, "rb").read().decode("utf-8-sig", errors="replace")
    eol = "\r\n" if "\r\n" in raw else "\n"
    text, notes = lab_build(raw.replace("\r\n", "\n"))
    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        fh.write(text.replace("\n", eol))
    for n in notes:
        print("  LAB", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
