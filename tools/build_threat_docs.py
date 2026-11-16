#!/usr/bin/env python3
"""
build_threat_docs.py - generate every threat README, the index and the ATT&CK Navigator layers.

Nothing in a threat README is written by hand: the words live in threat.yml, docs/ and each
detection.yml; the status of every matrix row comes from the last test run (docs/results.json).
So the coverage matrix can never claim more than the tests have proven.

    python tools/build_threat_docs.py
"""
import json
import os
import sys
import urllib.parse

import threatkit as tk

RESULTS = os.path.join(tk.ROOT, "docs", "results.json")
REPO = "azdabat/MTDF-Novel-Threats"

STATUS = {   # key: (label, mermaid class, navigator colour, score)
    "validated": ("✅ Validated", "ok", "#2ea043", 100),
    "partial":   ("🟡 Partly validated", "part", "#d29922", 70),
    "failing":   ("❌ Failing", "bad", "#f85149", 40),
    "awaiting":  ("⏳ Awaiting first run", "wait", "#d29922", 50),
    "telemetry": ("🧪 Awaiting telemetry", "wait", "#d29922", 30),
    "boundary":  ("⚠️ Coverage boundary", "edge", "#8b949e", 10),
    "planned":   ("🔲 Planned", "todo", "#8b949e", 5),
}


def load_results():
    if not os.path.exists(RESULTS):
        return {}, None
    data = json.load(open(RESULTS, encoding="utf-8"))
    by_det = {}
    for t in data.get("tests", []):
        by_det.setdefault((t["tactic"], t["detection"]), []).append(t)
    return by_det, data.get("run_utc")


def det_status(slug, name, ddir, results):
    tests = [f for f in os.listdir(ddir) if f.startswith("test") and f.endswith(".yml")]
    res = results.get((slug, name), [])
    if not tests:
        return "telemetry", res, 0
    if not res:
        return "awaiting", res, len(tests)
    passed = sum(1 for r in res if r["status"] in ("pass", "known"))
    if passed == len(res):
        return "validated", res, len(tests)
    return ("partial" if passed else "failing"), res, len(tests)


def row_status(row, det_states):
    if row.get("boundary"):
        return "boundary"
    if row.get("planned"):
        return "planned"
    states = [det_states[d][0] for d in row.get("detections") or [] if d in det_states]
    if not states:
        return "planned"
    if all(s == "validated" for s in states):
        return "validated"
    if any(s == "validated" for s in states):
        return "partial"
    for s in ("failing", "awaiting", "telemetry"):
        if s in states:
            return s
    return "partial"


def tech_links(techs):
    return ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in techs)


def mermaid(rows, statuses):
    lines = ["```mermaid", "flowchart LR"]
    stages, seen = [], {}
    for row, st in zip(rows, statuses):
        stage = row["stage"]
        if stage not in seen:
            seen[stage] = []
            stages.append(stage)
        seen[stage].append(st)
    rank = ["validated", "partial", "awaiting", "telemetry", "failing", "boundary", "planned"]
    for i, s in enumerate(stages):
        best = min(seen[s], key=rank.index)
        lines.append(f'    S{i}["{s}"]:::{STATUS[best][1]}')
    for i in range(len(stages) - 1):
        lines.append(f"    S{i} --> S{i + 1}")
    lines += ["    classDef ok fill:#0d2a17,stroke:#2ea043,color:#7ee2a8",
              "    classDef part fill:#2b2111,stroke:#d29922,color:#f2cc60",
              "    classDef wait fill:#2b2111,stroke:#d29922,color:#f2cc60",
              "    classDef bad fill:#2d1214,stroke:#f85149,color:#ffa198",
              "    classDef edge fill:#1c2128,stroke:#8b949e,color:#c9d1d9",
              "    classDef todo fill:#1c2128,stroke:#8b949e,color:#8b949e,stroke-dasharray: 4 3",
              "```"]
    return "\n".join(lines)


def build_threat(tdir, results, run_utc):
    t = tk.load_yaml(os.path.join(tdir, "threat.yml"))
    slug = os.path.basename(tdir)
    rows = t.get("attack_surface") or []
    det_dirs = {os.path.basename(d): d for d in tk.detection_dirs(tdir)}
    det_meta = {n: tk.load_yaml(os.path.join(d, "detection.yml")) for n, d in det_dirs.items()}
    det_states = {n: det_status(slug, n, d, results) for n, d in det_dirs.items()}
    statuses = [row_status(r, det_states) for r in rows]
    covered = sum(1 for s in statuses if s in ("validated", "partial"))
    with_rule = sum(1 for r in rows if r.get("detections"))

    L = [f"# {t['name']}", ""]
    badges = [f"**Type:** {t['type']}", f"**Status:** {t['status']}"]
    if t.get("first_seen"):
        badges.append(f"**First seen:** {t['first_seen']}")
    badges.append(f"**Platforms:** {', '.join(t.get('platforms') or [])}")
    if t.get("cves"):
        badges.append(f"**CVE:** {', '.join(str(c) for c in t['cves'])}")
    L += [" · ".join(badges), ""]
    L += [f"> **Coverage:** {covered} of {len(rows)} attack-surface rows validated against recorded telemetry · "
          f"{with_rule} have a detection · {len(det_dirs)} detections"
          + (f" · last run {run_utc}" if run_utc else " · not yet run"), ""]
    L += ["## Summary", "", str(t["summary"]).strip(), "", "## Threat model", "", str(t["threat_model"]).strip(), ""]

    L += ["## Kill chain and coverage", "", mermaid(rows, statuses), ""]
    L += ["## Attack-surface matrix", "",
          "Each row is one way the threat operates, the minimum truth it cannot avoid leaving, and what covers it. "
          "Status comes from the last test run.", "",
          "| Stage | Vector | ATT&CK | Minimum truth | Covered by | Status |", "|---|---|---|---|---|---|"]
    for row, st in zip(rows, statuses):
        if row.get("detections"):
            cov = "<br>".join(f"[`{d}`](detections/{d})" for d in row["detections"])
        elif row.get("boundary"):
            cov = f"*Boundary:* {row['boundary']}"
        else:
            cov = f"*Planned:* {row['planned']}"
        for c in row.get("cousins") or []:
            cov += f"<br>cousin: [{c['name']}]({c['url']})"
        cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ").strip()   # noqa: E731
        L.append(f"| {cell(row['stage'])} | {cell(row['vector'])} | {tech_links(row.get('techniques') or [])} | "
                 f"{cell(row['minimum_truth'])} | {cov} | {STATUS[st][0]} |")
    L.append("")

    def det_row(n):
        m = det_meta[n]
        st, res, ntests = det_states[n]
        rule = os.path.basename(tk.rule_file(det_dirs[n]) or "")
        passed = sum(1 for r in res if r["status"] in ("pass", "known"))
        tests = f"{passed}/{ntests} passing" if res else (f"{ntests} written" if ntests else "-")
        return (f"| [**{m.get('title', n)}**](detections/{n}/{rule}) | {m.get('architecture', '')} | "
                f"{tk.at.DISPLAY.get(m.get('tactic'), m.get('tactic', ''))} | {m.get('minimum_truth', '')} | "
                f"{tests} | {STATUS[st][0]} |")

    order = lambda n: (tk.at.ORDER.get(det_meta[n].get("tactic"), 99), n)       # noqa: E731
    L += ["## Detections", ""]
    for tier, label in tk.TIERS.items():
        names = sorted((n for n in det_dirs if det_meta[n].get("tier", "core") == tier), key=order)
        if not names:
            continue
        blurb = ("The sensors that cover the threat's main path." if tier == "core" else
                 "Adjacent sensors (MTDF *cousins*) that catch the variants the core sensors would miss: "
                 "renamed runtimes, persistence, staging, supply chain and Electron.")
        L += [f"### {label}", "", blurb, "",
              "| Detection | Architecture | Tactic | Minimum truth | Tests | Result |", "|---|---|---|---|---|---|"]
        L += [det_row(n) for n in names] + [""]

    variants = t.get("variants") or []
    if variants:
        cols = sorted(det_dirs, key=lambda n: (0 if det_meta[n].get("tier", "core") == "core" else 1, order(n)))
        short = {n: n.replace("nodejs_", "").replace("_", " ") for n in cols}
        by_test = {}
        for n in cols:
            for r in det_states[n][1]:
                by_test[(n, tk.capture_of_test(r["test"]))] = r
        caps_now = tk.captures(tdir)
        L += ["## Variant coverage", "",
              "Each row is one way the threat can be carried out, reproduced on the lab VM; each column is a detection. "
              "**Fires** means the test expects an alert and pins the variant's own event; **silent** means the "
              "benign workflow must raise nothing. A detection that should not see a variant has no cell.", "",
              "| Variant | " + " | ".join(short[n] for n in cols) + " |", "|---" * (len(cols) + 1) + "|"]
        for v in variants:
            cells = []
            for n in cols:
                tests = [x for x in (det_meta[n].get("tests") or []) if v["id"] in (x.get("variants") or [])]
                if not tests:
                    cells.append("")
                    continue
                silent = (tests[0].get("expect") or {}).get("row_count") == 0
                word = "silent" if silent else "fires"
                r = by_test.get((n, tests[0].get("capture")))
                if tests[0].get("capture") not in caps_now:
                    cells.append(f"🧪 {word}")
                elif r is None:
                    cells.append(f"⏳ {word}")
                elif r["status"] in ("pass", "known"):
                    cells.append(f"✅ {word}")
                else:
                    cells.append(f"❌ {word}")
            L.append(f"| **{v['id']}** {v['name']} | " + " | ".join(cells) + " |")
        L += ["", "🧪 capture not registered yet · ⏳ test built, not run yet · ✅ passing · ❌ failing", ""]
        L += ["<details><summary>Variant descriptions</summary>", "",
              "| Variant | What happens | Capture | Emulation |", "|---|---|---|---|"]
        for v in variants:
            L.append(f"| **{v['id']}** {v['name']} | {v['description']} | `{v['capture']}` | "
                     f"[`{os.path.basename(v.get('emulation', ''))}`]({v.get('emulation', '')}) |")
        L += ["", "</details>", ""]

    L += ["## Deployment", "",
          "How each detection goes into production. Atomic sensors index or route; composites alert. "
          "The general model is in [deployment-model.md](../../docs/deployment-model.md).", "",
          "| Detection | Tier | Mode | Microsoft Defender XDR | Microsoft Sentinel | Why |", "|---|---|---|---|---|---|"]
    for n in sorted(det_dirs, key=lambda n: (0 if det_meta[n].get("tier", "core") == "core" else 1, order(n))):
        m = det_meta[n]
        d = m.get("deploy") or {}
        L.append(f"| {m.get('title', n)} | {tk.TIERS.get(m.get('tier', 'core'), '')} | "
                 f"{tk.DEPLOY_MODES.get(d.get('mode'), '')} | {d.get('defender', '')} | {d.get('sentinel', '')} | {d.get('why', '')} |")
    L.append("")

    caps = tk.captures(tdir)
    L += ["## Telemetry", "",
          "Raw Sysmon from the lab emulation, kept with the threat. It is what every test is built from, "
          "and a ready-made dataset for hunting and forensic practice.", ""]
    if caps:
        L += ["| Dataset | What produced it | Window (UTC) | Events | SHA-256 |", "|---|---|---|---|---|"]
        for cid, (_, m) in caps.items():
            m = m or {}
            ev = ", ".join(f"EID {k}: {v}" for k, v in (m.get("sysmon_event_ids") or {}).items())
            emu = f"[`{os.path.basename(m['emulation'])}`]({m['emulation']})" if m.get("emulation") else "-"
            w = m.get("window_utc") or {}
            L.append(f"| [`{cid}`](telemetry/{cid}.json) — {m.get('title', '')} | {emu} | "
                     f"{w.get('start', '')[:19]} → {w.get('end', '')[:19]} | {ev} | `{str(m.get('sha256', ''))[:12]}…` |")
    else:
        L.append("*No capture registered yet - see [emulation](emulation/README.md).*")
    L.append("")

    L += ["## Reproduce it", "", "```powershell",
          f"# 1. lab VM (Sysmon): run the emulation in emulation/, export Sysmon to JSON",
          f"# 2. repo root:",
          f"python tools\\add_capture.py --threat {slug} --capture <export>.json --id <capture_id> --title \"...\"",
          "powershell -ExecutionPolicy Bypass -File lab.ps1", "```", ""]
    L += ["## Read more", "",
          "- [Tradecraft](docs/tradecraft.md) — how the threat works, step by step",
          "- [Hunting](docs/hunting.md) — hunts that run over the telemetry and in a real tenant",
          "- [Forensics](docs/forensics.md) — artefacts, timelines and what each one proves",
          "- [Emulation](emulation/README.md) — the harmless lab reproduction", ""]
    if os.path.isfile(os.path.join(tdir, "docs", "lab-notes.md")):
        L.insert(-1, "- [Lab notes](docs/lab-notes.md) — how the detections were engineered: assumptions, bugs found, and why each fix was made")
    if os.path.isfile(os.path.join(tdir, "docs", "deployment.md")):
        L.insert(-1, "- [Deployment](docs/deployment.md) — rollout order, tuning and what each detection needs in Defender and Sentinel")
    layer = f"https://raw.githubusercontent.com/{REPO}/main/docs/navigator/{slug}.json"
    L += [f"🗺️ [ATT&CK Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL="
          f"{urllib.parse.quote(layer, safe='')}) for this threat", ""]
    if t.get("references"):
        L += ["## References", ""] + [f"- [{r['title']}]({r['url']})" for r in t["references"]] + [""]
    L += ["---", "*Generated by `tools/build_threat_docs.py` from `threat.yml`, `docs/` and the last test run. "
          "Edit those, not this file.*", ""]
    with open(os.path.join(tdir, "README.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))

    techs = {}
    for row, st in zip(rows, statuses):
        for tech in row.get("techniques") or []:
            cur = techs.get(tech)
            if cur is None or STATUS[st][3] > STATUS[cur][3]:
                techs[tech] = st
    nav = {"name": t["name"], "versions": {"attack": "16", "navigator": "4.9.1", "layer": "4.5"},
           "domain": "enterprise-attack", "description": f"MTDF coverage for {t['name']}",
           "techniques": [{"techniqueID": k, "score": STATUS[v][3], "color": STATUS[v][2],
                           "comment": STATUS[v][0], "enabled": True} for k, v in sorted(techs.items())],
           "legendItems": [{"label": STATUS[k][0], "color": STATUS[k][2]} for k in ("validated", "telemetry", "boundary")],
           "hideDisabled": False}
    os.makedirs(os.path.join(tk.ROOT, "docs", "navigator"), exist_ok=True)
    with open(os.path.join(tk.ROOT, "docs", "navigator", f"{slug}.json"), "w", encoding="utf-8") as fh:
        json.dump(nav, fh, indent=1)
    return {"slug": slug, "name": t["name"], "type": t["type"], "status": t["status"],
            "platforms": t.get("platforms") or [], "rows": len(rows), "covered": covered,
            "detections": len(det_dirs),
            "tests_pass": sum(sum(1 for r in s[1] if r["status"] in ("pass", "known")) for s in det_states.values()),
            "tests": sum(s[2] for s in det_states.values())}


def main():
    results, run_utc = load_results()
    index = [build_threat(d, results, run_utc) for d in tk.threat_dirs()]
    table = ["| Threat | Type | Status | Platforms | Matrix validated | Detections | Tests passing |",
             "|---|---|---|---|---|---|---|"]
    for i in index:
        table.append(f"| [**{i['name']}**](threats/{i['slug']}) | {i['type']} | {i['status']} | "
                     f"{', '.join(i['platforms'])} | {i['covered']}/{i['rows']} | {i['detections']} | "
                     f"{i['tests_pass']}/{i['tests']} |")
    block = "\n".join(table) + ("\n\n*Last test run: " + run_utc + "*" if run_utc else "\n\n*Not yet run.*")
    readme = os.path.join(tk.ROOT, "README.md")
    text = open(readme, encoding="utf-8").read()
    a, b = "<!-- THREATS:START -->", "<!-- THREATS:END -->"
    if a in text and b in text:
        text = text[:text.index(a) + len(a)] + "\n" + block + "\n" + text[text.index(b):]
        open(readme, "w", encoding="utf-8").write(text)
    print(f"docs built: {len(index)} threat README(s), index, Navigator layers"
          + (f" (results from {run_utc})" if run_utc else " (no results yet)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
