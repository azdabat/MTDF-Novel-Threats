#!/usr/bin/env python3
"""
validate_threats.py - enforce the threat format (THREAT_FORMAT.md) on every threat.

Uniformity is what lets a reader open any threat and find the same things in the same
places, and what lets the docs and the coverage matrix be generated. This is the gate.

  ERROR   (exit 1)  missing or malformed threat.yml / detection.yml fields, missing docs,
                    a matrix row pointing at a detection that doesn't exist, a detection the
                    matrix never mentions, a capture with no dataset metadata
  PENDING (exit 0)  a test waiting for its capture - normal while a threat is being built

    python tools/validate_threats.py
"""
import os
import sys

import threatkit as tk

REQUIRED_THREAT = ["name", "slug", "type", "status", "platforms", "summary", "threat_model", "attack_surface"]
REQUIRED_DET = ["title", "architecture", "tier", "tactic", "techniques", "minimum_truth", "data_sources", "source_rule", "deploy"]


def check_threat(tdir):
    errs, pend = [], []
    slug = os.path.basename(tdir)
    E = lambda m: errs.append(f"{slug}: {m}")            # noqa: E731
    meta_path = os.path.join(tdir, "threat.yml")
    if not os.path.isfile(meta_path):
        return [f"{slug}: threat.yml missing"], []
    t = tk.load_yaml(meta_path)

    for k in REQUIRED_THREAT:
        if not t.get(k):
            E(f"threat.yml: '{k}' is empty")
    if t.get("slug") and t["slug"] != slug:
        E(f"threat.yml: slug '{t['slug']}' does not match folder '{slug}'")
    if t.get("type") and t["type"] not in tk.TYPES:
        E(f"threat.yml: type must be one of {tk.TYPES}")
    if t.get("status") and t["status"] not in tk.STATUSES:
        E(f"threat.yml: status must be one of {tk.STATUSES}")
    if t.get("type") == "zero-day" and not t.get("cves"):
        E("threat.yml: a zero-day needs cves: (or 'none assigned')")
    for d in tk.DOCS:
        p = os.path.join(tdir, "docs", d)
        if not os.path.isfile(p) or os.path.getsize(p) < 200:
            E(f"docs/{d} missing or a stub")
    if not os.path.isfile(os.path.join(tdir, "emulation", "README.md")):
        E("emulation/README.md missing")

    dets = {os.path.basename(d): d for d in tk.detection_dirs(tdir)}
    referenced = set()
    for i, row in enumerate(t.get("attack_surface") or [], 1):
        where = f"attack_surface[{i}]"
        for k in ("stage", "vector", "minimum_truth"):
            if not row.get(k):
                E(f"{where}: '{k}' is empty")
        techs = row.get("techniques") or []
        if not techs or any(not tk.TECH_RX.match(str(x)) for x in techs):
            E(f"{where}: techniques must be ATT&CK IDs like T1059.007")
        kinds = [k for k in ("detections", "boundary", "planned") if row.get(k)]
        if len(kinds) != 1:
            E(f"{where}: needs exactly one of detections / boundary / planned (has {kinds or 'none'})")
        for name in row.get("detections") or []:
            referenced.add(name)
            if name not in dets:
                E(f"{where}: detection '{name}' has no folder in detections/")
    for name in sorted(set(dets) - referenced):
        E(f"detections/{name} is not in the attack_surface matrix")

    variant_ids = {}
    for v in t.get("variants") or []:
        for k in ("id", "name", "capture", "description"):
            if not v.get(k):
                E(f"variants: '{k}' is empty in {v}")
        if v.get("id") in variant_ids:
            E(f"variants: duplicate id {v['id']}")
        variant_ids[v.get("id")] = v

    caps = tk.captures(tdir)
    for cid, (_, meta) in caps.items():
        if meta is None:
            E(f"telemetry/{cid}.json has no {cid}.yml (register it with tools/add_capture.py)")
    for name, ddir in dets.items():
        m = tk.load_yaml(os.path.join(ddir, "detection.yml"))
        for k in REQUIRED_DET:
            if not m.get(k):
                E(f"{name}/detection.yml: '{k}' is empty")
        if str(m.get("minimum_truth", "")).upper().startswith("TODO"):
            E(f"{name}/detection.yml: minimum_truth is still TODO")
        if m.get("architecture") and m["architecture"] not in tk.ARCHITECTURES:
            E(f"{name}/detection.yml: architecture must be one of {tk.ARCHITECTURES}")
        if m.get("tier") and m["tier"] not in tk.TIERS:
            E(f"{name}/detection.yml: tier must be one of {list(tk.TIERS)}")
        dep = m.get("deploy") or {}
        if dep and (dep.get("mode") not in tk.DEPLOY_MODES or not dep.get("defender") or not dep.get("sentinel")):
            E(f"{name}/detection.yml: deploy needs mode ({'/'.join(tk.DEPLOY_MODES)}), defender and sentinel")
        for test in m.get("tests") or []:
            for vid in test.get("variants") or []:
                if vid not in variant_ids:
                    E(f"{name}: test names variant '{vid}', which threat.yml does not define")
                elif variant_ids[vid].get("capture") != test.get("capture"):
                    E(f"{name}: variant '{vid}' lives in capture '{variant_ids[vid]['capture']}', not '{test.get('capture')}'")
        if m.get("tactic") and m["tactic"] not in tk.at.SLUGS:
            E(f"{name}/detection.yml: unknown tactic '{m['tactic']}'")
        if not tk.rule_file(ddir):
            E(f"{name}: no .kql rule")
        if not m.get("tests"):
            pend.append(f"{slug}/{name}: no test yet - add one under tests: in detection.yml")
        for test in m.get("tests") or []:
            cid = test.get("capture")
            if cid not in caps:
                pend.append(f"{slug}/{name}: waiting for capture '{cid}' (tools/add_capture.py)")
            elif not os.path.isfile(os.path.join(ddir, f"test_{cid}.yml")):
                E(f"{name}: capture '{cid}' is registered but test_{cid}.yml was not built - re-run add_capture.py")
    return errs, pend


def main():
    threats = tk.threat_dirs()
    all_err, all_pend = [], []
    for tdir in threats:
        e, p = check_threat(tdir)
        all_err += e
        all_pend += p
        print(f"  {'ERROR  ' if e else 'ok     '} {os.path.basename(tdir)}"
              f"{f'  ({len(p)} pending)' if p else ''}")
    for e in all_err:
        print(f"    ERROR   {e}")
    for p in all_pend:
        print(f"    PENDING {p}")
    print(f"\n{len(threats)} threat(s): {len(all_err)} error(s), {len(all_pend)} pending")
    return 1 if all_err else 0


if __name__ == "__main__":
    sys.exit(main())
