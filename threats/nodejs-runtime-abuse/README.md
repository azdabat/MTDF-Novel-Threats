# Node.js Runtime Abuse

**Type:** tradecraft · **Status:** active · **First seen:** 2023 (loader and C2 use in commodity and targeted campaigns) · **Platforms:** Windows, Linux

> **Coverage:** 8 of 15 attack-surface rows validated against recorded telemetry · 11 have a detection · 9 detections · last run 2026-11-16 18:46 UTC

## Summary

Attackers use Node.js the way they once used PowerShell: a signed, trusted runtime that runs whatever JavaScript it is handed. It appears at both ends of an intrusion. On servers, a web application's own node process becomes the foothold when an attacker gets code running in it (unsafe deserialisation, template injection, eval / vm escapes, prototype pollution, command injection) and then shells out. On workstations, malware ships node.exe and a .js payload into a user-writable folder and runs it from a script host or LNK, and the payload talks to its operator directly from node - in some campaigns resolving the C2 address from a public blockchain so it never appears in the code.

## Threat model

Behaviour-first and patch-agnostic. Every code-execution vector, known or zero-day, has to land in the same place to do anything useful: node spawning a process, node running from somewhere it should not, or node talking to somewhere a developer's node would not. Those three are the minimum truths, so the coverage does not depend on which bug or which loader got the attacker there. Allowlists (developer parents, npm shims, package registries, GitHub) only lower a score, never exclude, because attackers stage payloads in the same places.

## Kill chain and coverage

```mermaid
flowchart LR
    S0["Code execution in node"]:::ok
    S1["Loader execution"]:::ok
    S2["Staging"]:::wait
    S3["Persistence"]:::wait
    S4["Command and control"]:::ok
    S5["Supply chain"]:::part
    S6["Defense evasion"]:::wait
    S0 --> S1
    S1 --> S2
    S2 --> S3
    S3 --> S4
    S4 --> S5
    S5 --> S6
    classDef ok fill:#0d2a17,stroke:#2ea043,color:#7ee2a8
    classDef part fill:#2b2111,stroke:#d29922,color:#f2cc60
    classDef wait fill:#2b2111,stroke:#d29922,color:#f2cc60
    classDef bad fill:#2d1214,stroke:#f85149,color:#ffa198
    classDef edge fill:#1c2128,stroke:#8b949e,color:#c9d1d9
    classDef todo fill:#1c2128,stroke:#8b949e,color:#8b949e,stroke-dasharray: 4 3
```

## Attack-surface matrix

Each row is one way the threat operates, the minimum truth it cannot avoid leaving, and what covers it. Status comes from the last test run.

| Stage | Vector | ATT&CK | Minimum truth | Covered by | Status |
|---|---|---|---|---|---|
| Code execution in node | Unsafe deserialisation (node-serialize), template injection (pug, ejs), eval / vm sandbox escape (vm2), prototype pollution, command injection - any bug that runs attacker code in node | [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1190](https://attack.mitre.org/techniques/T1190/) | node spawns a child process | [`nodejs_child_process_atomic`](detections/nodejs_child_process_atomic)<br>[`nodejs_child_process_router`](detections/nodejs_child_process_router) | ✅ Validated |
| Code execution in node | Shell, LOLBin, downloader or encoded PowerShell launched by node (Windows wraps every exec() in cmd.exe /d /s /c) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1218](https://attack.mitre.org/techniques/T1218/) | node spawns a shell or tool carrying attack primitives on its command line | [`nodejs_child_process_router`](detections/nodejs_child_process_router) | ✅ Validated |
| Code execution in node | Python, Perl or PowerShell run with inline decoding (b64decode, FromBase64String, atob) from node | [T1059.006](https://attack.mitre.org/techniques/T1059/006/), [T1027](https://attack.mitre.org/techniques/T1027/) | node spawns an interpreter with inline encoded code | [`nodejs_child_process_router`](detections/nodejs_child_process_router) | ✅ Validated |
| Loader execution | node.exe and a .js payload dropped in AppData / Temp / Downloads and run by a script host, shell or LNK | [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1218](https://attack.mitre.org/techniques/T1218/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | a Node.js runtime runs from, or runs a script from, a user-writable location | [`nodejs_loader_execution`](detections/nodejs_loader_execution) | ✅ Validated |
| Loader execution | Renamed node.exe, or a pkg / nexe single-file bundle carrying the node runtime | [T1036.003](https://attack.mitre.org/techniques/T1036/003/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | a process whose PE metadata says node.exe / Node.js runs, or spawns children, under another name | [`nodejs_loader_execution`](detections/nodejs_loader_execution)<br>[`nodejs_child_process_atomic`](detections/nodejs_child_process_atomic)<br>[`nodejs_child_process_router`](detections/nodejs_child_process_router) | ✅ Validated |
| Staging | node writes its next stage (exe, dll, ps1, cmd, hta, lnk) to a writable path or the Startup folder | [T1105](https://attack.mitre.org/techniques/T1105/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | a Node.js runtime writes an executable or script file type | [`nodejs_file_dropper`](detections/nodejs_file_dropper) | 🧪 Awaiting telemetry |
| Persistence | Run / RunOnce / Winlogon value or service ImagePath launching a script with node or a renamed runtime | [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | an autostart value is set to launch a JavaScript file | [`nodejs_persistence_autostart`](detections/nodejs_persistence_autostart)<br>cousin: [Registry persistence - TaskCache and Service ImagePath (MTDF-Detection-Tests)](https://github.com/azdabat/MTDF-Detection-Tests/tree/main/detections/persistence/registry_service_taskcache_persistence) | 🧪 Awaiting telemetry |
| Persistence | Scheduled task created with node.exe plus a script as its action | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | schtasks /create whose /tr runs node or a .js file | *Planned:* Add node / .js to the script-engine list of Scheduled_Task_Abuse in MTDF-Detection-Tests<br>cousin: [Scheduled Task Abuse (MTDF-Detection-Tests)](https://github.com/azdabat/MTDF-Detection-Tests/tree/main/detections/execution/scheduled_task_abuse) | 🔲 Planned |
| Command and control | C2 address resolved from a public blockchain (smart-contract read over a public RPC endpoint - EtherHiding / EtherRAT pattern) | [T1102](https://attack.mitre.org/techniques/T1102/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | a Node.js runtime connects out to a public address | [`nodejs_outbound_c2`](detections/nodejs_outbound_c2) | ✅ Validated |
| Command and control | Direct-to-IP, non-web port or repeated polling from a node runtime in a writable path | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1571](https://attack.mitre.org/techniques/T1571/) | a Node.js runtime connects out to a public address | [`nodejs_outbound_c2`](detections/nodejs_outbound_c2)<br>[`https_beacon_shape`](detections/https_beacon_shape) | ✅ Validated |
| Supply chain | Malicious npm / yarn / pnpm preinstall or postinstall script reaching the network, decoding or using a LOLBin | [T1195.002](https://attack.mitre.org/techniques/T1195/002/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | a package manager's node process starts a child with network, decode or LOLBin primitives | [`npm_install_script_abuse`](detections/npm_install_script_abuse)<br>[`nodejs_child_process_router`](detections/nodejs_child_process_router) | 🟡 Partly validated |
| Defense evasion | Electron app (VS Code, Slack, Discord, Teams classic) run as node with a script file via ELECTRON_RUN_AS_NODE | [T1218](https://attack.mitre.org/techniques/T1218/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | an Electron app binary is launched with a JavaScript file argument outside its own resources | [`electron_as_node_execution`](detections/electron_as_node_execution) | 🧪 Awaiting telemetry |
| Defense evasion | Electron app run as node with inline code (-e), so there is no script argument | [T1218](https://attack.mitre.org/techniques/T1218/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | an Electron app spawns a shell or LOLBin carrying attack primitives | *Planned:* Electron_Child_Process_Abuse - the router's primitives applied to Electron apps as parents | 🔲 Planned |
| Defense evasion | The ELECTRON_RUN_AS_NODE switch itself | [T1218](https://attack.mitre.org/techniques/T1218/) | an environment variable on the launching process | *Boundary:* Defender does not record environment variables; the launch shape (script argument) and the children are what is visible | ⚠️ Coverage boundary |
| Loader execution | Linux: node run from /tmp, /dev/shm or a hidden home directory by a web server or cron | [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | a Node.js runtime runs a script from a world-writable path on Linux | *Planned:* NodeJS_Linux_Loader - same minimum truth with Linux paths (the collector and router already cover Linux children) | 🔲 Planned |

## Detections

### Core sensors

The sensors that cover the threat's main path.

| Detection | Architecture | Tactic | Minimum truth | Tests | Result |
|---|---|---|---|---|---|
| [**Node.js Child Process - Primitive Collector**](detections/nodejs_child_process_atomic/NodeJS_ChildProcess_Atomic.kql) | Primitive collector | Execution (TA0002) | Node.js spawned a child process (zero inference: no claim of intent or malice) | 1/1 passing | ✅ Validated |
| [**Node.js Child Process Abuse - Router**](detections/nodejs_child_process_router/NodeJS_ChildProcess_Abuse_Router.kql) | Router | Execution (TA0002) | node spawns a shell, interpreter, downloader or LOLBin carrying attack primitives on its command line | 1/1 passing | ✅ Validated |
| [**Node.js Loader Execution**](detections/nodejs_loader_execution/NodeJS_Loader_Execution.kql) | Composite sensor | Execution (TA0002) | A Node.js runtime (by name or PE metadata) runs from, or runs a script from, a user-writable location | 1/1 passing | ✅ Validated |
| [**HTTPS Beacon Shape - Repetition and Controlled Jitter**](detections/https_beacon_shape/C2_HTTPS_Jitter_BeaconShape_LowCPU_v1_1.kql) | Composite (L3) | Command and Control (TA0011) | A non-browser process connects to the same destination at a regular interval | 1/1 passing | ✅ Validated |
| [**Node.js Outbound C2**](detections/nodejs_outbound_c2/NodeJS_Outbound_C2.kql) | Composite sensor | Command and Control (TA0011) | A Node.js runtime opens an outbound connection to a public address | 1/1 passing | ✅ Validated |

### Cousin Pack

Adjacent sensors (MTDF *cousins*) that catch the variants the core sensors would miss: renamed runtimes, persistence, staging, supply chain and Electron.

| Detection | Architecture | Tactic | Minimum truth | Tests | Result |
|---|---|---|---|---|---|
| [**npm Install-Script Abuse**](detections/npm_install_script_abuse/NPM_Install_Script_Abuse.kql) | Composite sensor | Initial Access (TA0001) | A package manager's node process starts a child whose command line reaches the network, decodes, or uses a LOLBin | - | 🧪 Awaiting telemetry |
| [**Node.js Persistence - Autostart Runs a Script**](detections/nodejs_persistence_autostart/NodeJS_Persistence_Autostart.kql) | Composite sensor | Persistence (TA0003) | An autostart value (Run, RunOnce, Winlogon, service ImagePath) is set to launch a JavaScript file | - | 🧪 Awaiting telemetry |
| [**Electron App Run as Node**](detections/electron_as_node_execution/Electron_As_Node_Execution.kql) | Composite sensor | Defense Evasion (TA0005) | An Electron app binary is launched with a JavaScript file argument that is not part of the app's own resources | - | 🧪 Awaiting telemetry |
| [**Node.js File Dropper**](detections/nodejs_file_dropper/NodeJS_File_Dropper.kql) | Composite sensor | Command and Control (TA0011) | A Node.js runtime writes an executable or script file type, or anything into a Startup folder | - | 🧪 Awaiting telemetry |

## Variant coverage

Each row is one way the threat can be carried out, reproduced on the lab VM; each column is a detection. **Fires** means the test expects an alert and pins the variant's own event; **silent** means the benign workflow must raise nothing. A detection that should not see a variant has no cell.

| Variant | child process atomic | child process router | loader execution | https beacon shape | outbound c2 | npm install script abuse | persistence autostart | electron as node execution | file dropper |
|---|---|---|---|---|---|---|---|---|---|
| **V0** Baseline loader chain | ✅ fires | ✅ fires | ✅ fires | ✅ fires | ✅ fires |  |  |  |  |
| **V1** Renamed runtime | 🧪 fires | 🧪 fires | 🧪 fires |  |  |  |  |  |  |
| **V2** Non-web-port C2 |  |  |  |  | 🧪 fires |  |  |  |  |
| **V3** Run-key persistence |  |  |  |  |  |  | 🧪 fires |  |  |
| **V4** Stage and Startup drop |  |  |  |  |  |  |  |  | 🧪 fires |
| **V5** npm postinstall |  | 🧪 fires |  |  |  | 🧪 fires |  |  |  |
| **V6** Electron run as node |  |  | 🧪 fires |  |  |  |  | 🧪 fires |  |
| **B** Benign developer workflow |  | 🧪 silent | 🧪 silent |  | 🧪 silent | 🧪 silent | 🧪 silent | 🧪 silent | 🧪 silent |

🧪 capture not registered yet · ⏳ test built, not run yet · ✅ passing · ❌ failing

<details><summary>Variant descriptions</summary>

| Variant | What happens | Capture | Emulation |
|---|---|---|---|
| **V0** Baseline loader chain | A copied node.exe in %TEMP% runs a script; it launches an IEX cradle, encoded PowerShell and certutil, then polls a public Ethereum RPC endpoint 25 times | `node_lab_v1` | [`mtdf_node_lab.ps1`](emulation/mtdf_node_lab.ps1) |
| **V1** Renamed runtime | node.exe copied to Downloads as update.exe; its child is encoded PowerShell | `node_variants_v1` | [`mtdf_node_variants.ps1`](emulation/mtdf_node_variants.ps1) |
| **V2** Non-web-port C2 | The renamed runtime opens 6 connections to port 4444 on a public test host | `node_variants_v1` | [`mtdf_node_variants.ps1`](emulation/mtdf_node_variants.ps1) |
| **V3** Run-key persistence | HKCU Run value MTDFUpdater launching update.exe payload.js | `node_variants_v1` | [`mtdf_node_variants.ps1`](emulation/mtdf_node_variants.ps1) |
| **V4** Stage and Startup drop | node writes a .cmd into the Startup folder and a .ps1 into %TEMP% | `node_variants_v1` | [`mtdf_node_variants.ps1`](emulation/mtdf_node_variants.ps1) |
| **V5** npm postinstall | npm install of a package whose postinstall script runs curl | `node_variants_v1` | [`mtdf_node_variants.ps1`](emulation/mtdf_node_variants.ps1) |
| **V6** Electron run as node | An Electron-named binary (Code.exe, a node stand-in) launched with a script from %TEMP% | `node_variants_v1` | [`mtdf_node_variants.ps1`](emulation/mtdf_node_variants.ps1) |
| **B** Benign developer workflow | npm install, an app fetching from registry.npmjs.org, npm run build with node -e, npx and a node -e one-liner: every detection must stay silent | `node_benign_v1` | [`mtdf_node_benign.ps1`](emulation/mtdf_node_benign.ps1) |

</details>

## Deployment

How each detection goes into production. Atomic sensors index or route; composites alert. The general model is in [deployment-model.md](../../docs/deployment-model.md).

| Detection | Tier | Mode | Microsoft Defender XDR | Microsoft Sentinel | Why |
|---|---|---|---|---|---|
| Node.js Child Process - Primitive Collector | Core sensors | Index - collected, never alerts | Hunting query saved as a function; not a detection | Summary rule into a custom table, daily, 30-day retention | Zero-inference index: every node child, kept so routers, composites and hunts can look back 30 days |
| Node.js Child Process Abuse - Router | Core sensors | Triage - routes to a queue | Custom detection rule, every 1 hour | Scheduled analytics rule, every 1 hour over 1 hour, incidents grouped by host | Routes each node child to the composite that owns its noise domain; medium-fidelity alerts for a triage queue |
| Node.js Loader Execution | Core sensors | Alert - raises an incident | Custom detection rule, every 1 hour | Scheduled analytics rule, every 1 hour over 1 day (30-day baseline) | High-fidelity: node from a writable path is rare on any device that is not a developer workstation |
| HTTPS Beacon Shape - Repetition and Controlled Jitter | Core sensors | Alert - raises an incident | Custom detection rule, every 3 hours | Scheduled analytics rule, every 1 hour over 24 hours | Generic timing composite for any process; deploy estate-wide, not only for node |
| Node.js Outbound C2 | Core sensors | Alert - raises an incident | Custom detection rule, every 1 hour | Scheduled analytics rule, every 1 hour over 1 day | Process context plus destination: catches C2 that never looks like a beacon |
| npm Install-Script Abuse | Cousin Pack | Alert - raises an incident | Custom detection rule, every 1 hour (developer workstations and build agents) | Scheduled analytics rule, every 1 hour over 1 hour | Supply-chain execution on the machines that hold source code and publishing tokens |
| Node.js Persistence - Autostart Runs a Script | Cousin Pack | Alert - raises an incident | Custom detection rule, every 1 hour | Scheduled analytics rule, every 1 hour over 1 hour | Very rare in legitimate use; a script in a Run key is worth an alert on its own |
| Electron App Run as Node | Cousin Pack | Alert - raises an incident | Custom detection rule, every 1 hour | Scheduled analytics rule, every 1 hour over 1 hour | Turns most of the ELECTRON_RUN_AS_NODE boundary into a detection: the launch shape is visible even though the variable is not |
| Node.js File Dropper | Cousin Pack | Alert - raises an incident | Custom detection rule, every 1 hour | Scheduled analytics rule, every 1 hour over 1 hour | Startup-folder writes by node alert alone; writable-path drops pair with the loader |

## Telemetry

Raw Sysmon from the lab emulation, kept with the threat. It is what every test is built from, and a ready-made dataset for hunting and forensic practice.

| Dataset | What produced it | Window (UTC) | Events | SHA-256 |
|---|---|---|---|---|
| [`node_lab_v1`](telemetry/node_lab_v1.json) — Node.js lab emulation: loader, child processes, blockchain-RPC polling | [`mtdf_node_lab.ps1`](emulation/mtdf_node_lab.ps1) | 2026-11-16T17:50:36 → 2026-11-16T18:24:47 | EID 1: 96, EID 3: 178, EID 11: 1087, EID 22: 57 | `d4ac6da75aa0…` |

## Reproduce it

```powershell
# 1. lab VM (Sysmon): run the emulation in emulation/, export Sysmon to JSON
# 2. repo root:
python tools\add_capture.py --threat nodejs-runtime-abuse --capture <export>.json --id <capture_id> --title "..."
powershell -ExecutionPolicy Bypass -File lab.ps1
```

## Read more

- [Tradecraft](docs/tradecraft.md) — how the threat works, step by step
- [Hunting](docs/hunting.md) — hunts that run over the telemetry and in a real tenant
- [Forensics](docs/forensics.md) — artefacts, timelines and what each one proves
- [Emulation](emulation/README.md) — the harmless lab reproduction
- [Lab notes](docs/lab-notes.md) — how the detections were engineered: assumptions, bugs found, and why each fix was made
- [Deployment](docs/deployment.md) — rollout order, tuning and what each detection needs in Defender and Sentinel

🗺️ [ATT&CK Navigator layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fazdabat%2FMTDF-Novel-Threats%2Fmain%2Fdocs%2Fnavigator%2Fnodejs-runtime-abuse.json) for this threat

## References

- [Microsoft Threat Intelligence (Apr 2025) - Threat actors misuse Node.js to deliver malware and other malicious payloads](https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/)
- [Google Threat Intelligence - DPRK adopts EtherHiding (smart contracts as C2 / payload store)](https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding)
- [Node.js child_process documentation (exec wraps commands in a shell)](https://nodejs.org/api/child_process.html)
- [Original research - Node.js Child Process Abuse (MTDF)](https://github.com/azdabat/Novel-Tradecraft-Research-Emerging-Attack-Ecosystems/blob/main/Node.js%20Child%20Process%20Abuse.md)

---
*Generated by `tools/build_threat_docs.py` from `threat.yml`, `docs/` and the last test run. Edit those, not this file.*
