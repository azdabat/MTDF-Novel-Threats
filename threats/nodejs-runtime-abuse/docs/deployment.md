# Deployment: Node.js Runtime Abuse

The per-detection deployment table is in the [threat README](../README.md#deployment); the general model is in [deployment-model.md](../../../docs/deployment-model.md). This page is the rollout plan for this threat specifically.

## Rollout order

| Step | Detections | Where | Why first |
|---|---|---|---|
| 1 | `nodejs_child_process_atomic` (index) | Every device | History. Every later step and every hunt reads it. |
| 2 | `nodejs_loader_execution`, `nodejs_persistence_autostart`, `nodejs_file_dropper` | Every device | Highest fidelity: node from a writable path, a script in a Run key, node writing to Startup are rare outside an attack. |
| 3 | `electron_as_node_execution` | Every device | Rare and specific; turns most of the Electron boundary into coverage. |
| 4 | `nodejs_outbound_c2` | Every device | Needs a week of hunt mode to learn which non-developer devices legitimately run node services. |
| 5 | `npm_install_script_abuse` | Developer workstations and build agents first | Volume depends on how many packages with install scripts the estate uses; tune `BuildHelpers` in hunt mode. |
| 6 | `nodejs_child_process_router` | Every device, to a triage queue | Medium fidelity by design; it routes, then retires as the decomposed composites go live. |
| 7 | `https_beacon_shape` | Every device | Generic, any process; tune `BrowserLike` / `CommonCloudAgents` for the estate. |

## Device populations

Node behaves differently on three kinds of device, so measure noise per population in hunt mode:

- **Developer workstations**: node, npm, npx and Electron editors all day. Expect router and npm-rule volume; expect the loader to stay quiet unless developers run tools from Downloads.
- **Servers running Node.js services**: node is long-running and talks to its own dependencies. The C2 sensor needs their service destinations understood; child processes from a web service are rare and valuable.
- **Everyone else**: node should not exist. On these devices every Node.js sensor is close to high fidelity, and the collector's "first node on this device" signal is the strongest lead in the threat.

## Tuning knobs (in the variables at the top of each rule)

| Detection | Variable | What to add |
|---|---|---|
| Loader | `DevParents`, `NpmShimRx` | Your IDEs and terminals; a custom npm prefix if you use one |
| Outbound C2 | `DevHosts` | Internal package mirrors (Artifactory, Nexus, Verdaccio) |
| npm install scripts | `BuildHelpers` | Native-module helpers your builds rely on |
| Electron | `ElectronApps`, install folders | Your organisation's Electron apps and where they install |
| Router | `ManagedParents` | Your management agents that legitimately run node |

Every tuning change adds a step to [`mtdf_node_benign.ps1`](../emulation/mtdf_node_benign.ps1) that reproduces the noise, so the fix is tested and stays fixed.

## Expected volume

The lab cannot measure production volume. Record it in hunt mode per population, per day, and put the numbers here; they decide each detection's severity and whether it alerts or routes.
