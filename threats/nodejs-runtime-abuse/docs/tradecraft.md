# Tradecraft: Node.js Runtime Abuse

How the threat works, stage by stage, and the one thing each stage cannot avoid leaving behind. The full research write-up lives in [Node.js Child Process Abuse](https://github.com/azdabat/Novel-Tradecraft-Research-Emerging-Attack-Ecosystems/blob/main/Node.js%20Child%20Process%20Abuse.md); this page is the detection-engineering view of it.

## Why attackers use Node.js

- **It is trusted.** `node.exe` is signed by the OpenJS Foundation and is common on developer and build machines, so it rarely appears on blocklists.
- **It is complete.** HTTP, sockets, file system, crypto and process creation are all in the standard library: a payload needs no other binary.
- **It is portable.** The runtime is a single executable. Malware can carry its own copy into a user-writable folder, or bundle it into one EXE with `pkg` or `nexe`.
- **JavaScript is easy to obfuscate**, and a script file is not a PE, so many controls never inspect it.

## Stage 1: code execution inside a node process (servers)

Every server-side vector ends with attacker JavaScript running inside the application's own `node` process:

| Vector | How code runs | Typical first action |
|---|---|---|
| Unsafe deserialisation | `node-serialize` evaluates an IIFE hidden in a serialised object | `require('child_process').exec(...)` |
| Server-side template injection | pug / ejs / handlebars compile attacker input into a template function | same |
| `eval` / `vm` sandbox escape | `vm2` and similar sandboxes broken out of via prototype chains | same |
| Prototype pollution | Polluted options (`shell`, `env`, `NODE_OPTIONS`) change what a later legitimate spawn runs | a legitimate spawn now runs attacker code |
| Command injection | User input concatenated into an `exec()` string | the injected command |

**What it leaves behind:** to do anything beyond the process itself (recon, download, reverse shell), the code must start a process. On Windows, `exec()` always runs the command through `cmd.exe /d /s /c "..."`; on Linux through `/bin/sh -c "..."`. So the child the telemetry shows is usually the shell, with the real tool on its command line. **Minimum truth: node spawns a child process.**

## Stage 2: node as a malware loader (workstations)

Seen in 2025 malvertising campaigns (fake crypto-trading installers) and in ClickFix-style lures:

1. A user runs a fake installer, an LNK, or a pasted PowerShell command.
2. It drops `node.exe` (or uses an installed one) and a `.js` payload under `%AppData%`, `%LocalAppData%` or `%Temp%`.
3. A script host or shell launches `node.exe <payload>.js`, often with the window hidden.
4. The payload collects system information, sets persistence and starts C2.

**What it leaves behind:** a Node.js runtime executing from, or executing a script from, a user-writable location. Developer tooling runs node from `Program Files` against project folders; a loader does not. **Minimum truth: runtime or script in a writable path.** A renamed `node.exe` keeps its PE metadata (`OriginalFileName = node.exe`, product `Node.js`), so renaming does not hide it.

## Stage 3: command and control

- **Direct HTTPS / WebSocket** to an attacker host, often direct-to-IP or on a non-web port.
- **Blockchain-resolved C2 (EtherHiding).** The payload calls a read-only function on a smart contract through a public RPC endpoint (Infura, Alchemy, PublicNode, BSC data seeds). The contract returns the current C2 address or the next-stage payload. The operator can change it at any time, and there is nothing in the payload to block.
- **Polling** at a fixed interval with jitter.

**What it leaves behind:** node connecting out to a public address. A developer's node talks to package registries and code hosts; a loader's node talks to everything else. **Minimum truth: node connects out to a public address**, with the destination and the runtime's location deciding the score.

## Stage 4: persistence

A Run key, scheduled task or service pointing at `node.exe` plus a script in a writable folder. The autostart write is the minimum truth (a cousin of the TaskCache and Run-key detections in [MTDF-Detection-Tests](https://github.com/azdabat/MTDF-Detection-Tests)).

## Stage 5: supply chain

A malicious npm package runs code at install time through `preinstall` / `postinstall` scripts, inheriting the developer's privileges and network. npm runs those scripts with node and a shell, so the chain is `npm → node → sh/cmd → tool`.

## Variants: how each stage changes, and which sensor holds

Attackers vary the details; the minimum truths stay. Each variant below is reproduced by [`mtdf_node_variants.ps1`](../emulation/mtdf_node_variants.ps1), and the [variant coverage matrix](../README.md#variant-coverage) shows which detection catches it in the last test run.

| Id | Variant | What changes | What does not change (the truth that still holds) | Sensor |
|---|---|---|---|---|
| V1 | Renamed runtime | `node.exe` becomes `update.exe` | PE metadata still says `node.exe` / `Node.js` | loader, collector, router (metadata) |
| V2 | Non-web-port C2 | port 4444 instead of 443, no beacon timing | node connects out to a public address | outbound C2 |
| V3 | Run-key persistence | survives reboot through the registry | an autostart value launches a `.js` file | persistence |
| V4 | Staging and Startup drop | next stage written to disk | node writes an executable or script type | file dropper |
| V5 | npm postinstall | code runs during `npm install`, before the app ever starts | the package manager's child reaches the network | npm install scripts, router |
| V6 | Electron run as node | a signed editor binary runs the script | the app is launched with a script argument | Electron, loader |
| B | Developer workflow | — | none of the truths hold; every sensor must stay silent | all (precision) |

Building the variants changed the rules before any of them ran: the collector and router could not see a renamed runtime (fixed with PE-metadata matching), `npx` running from the npm cache would have met the loader's minimum truth (now scored down), and `node -e` in an `npm run` script would have fired the router as "encoded PowerShell" (now `-e` counts only with PowerShell). Each fix is recorded in its rule's header.

## Coverage boundaries

- **Electron (`ELECTRON_RUN_AS_NODE`).** VS Code, Slack and Discord are node inside. Setting this environment variable makes the app run plain JavaScript as node. Defender does not record environment variables, so the switch itself is a boundary. The launch is not: run with a script file, the app's command line carries that script, which its own helper processes never do, and `electron_as_node_execution` anchors on it. The inline form (`-e "..."`) leaves no script argument; its children are the planned `Electron_Child_Process_Abuse` sensor.
- **No child process, no file, no network.** Code that only reads memory or data inside the node process leaves no endpoint telemetry. Application-level logging is the only control there.
