# Lab notes: how this threat was engineered

The reasoning behind the detections, in the order it happened: what was assumed, what testing showed, and what changed because of it. The other docs say *what* the coverage is; this page says *why it looks the way it does*.

## 1. Starting point: two rules and a question

The work began with two existing MTDF rules: a primitive collector (every child of node, zero inference) and a router (triage by child-process family). The question was whether they covered Node.js abuse as attackers actually use it, not just as it is usually described.

Mapping the attack surface stage by stage (tradecraft.md) showed they covered one stage, code execution inside node, and that every server-side vector (deserialisation, template injection, sandbox escape, prototype pollution, command injection) lands in the same place: node spawning a process. That became the first minimum truth, and the reason the collector is the foundation rather than one rule among many.

## 2. Static review: bugs found before anything ran

Running the router through the pipeline (lint, then Microsoft's Kusto compiler against the Defender schema) and reading its scoring found:

- **Unreachable logic.** The managed-agent penalty tested a column the filter had already pinned to `node.exe`, so it could never apply.
- **The Windows shell wrapper.** Node's `exec()` always runs `cmd.exe /d /s /c "..."`, so the child is `cmd.exe` and the real tool is on its command line. Tool groups matched on `FileName` therefore never saw `certutil` or `curl` on Windows.
- **Scores that could not reach their own directives.** "Downloader + URL" scored 25 against a threshold of 30, so the HIGH directive written for it could never fire.

The existing C2 beacon rule did not compile at all: `SentBytes` / `ReceivedBytes` do not exist in `DeviceNetworkEvents`, and `partition by` takes a single column.

## 3. Designing variants found more bugs than testing

Writing down how an attacker would vary each stage (variants V1–V6) and what a developer does all day (benign workflow B) exposed three false negatives and false positives before any variant was run:

- **A renamed runtime was invisible.** The collector and router matched node by name; `update.exe` hid every child. Fixed by matching PE metadata (`OriginalFileName = node.exe`, product `Node.js`), which renaming does not change.
- **`npx` met the loader's minimum truth.** npx runs packages from `%LocalAppData%\npm-cache`, a user-writable path. Scored down, never excluded, so a payload hidden there still counts on the other signals.
- **`node -e` looked like encoded PowerShell.** The router's encoded-command pattern matched node's own `-e` (evaluate) flag, so `npm run build` with an inline script would have fired. `-e` now counts only when PowerShell is on the command line.

Lesson kept for every threat: **write the benign workflow before the rules ship.** It costs minutes and finds the noise that would otherwise be found by a SOC.

### A second benign review: what a developer's node launches every day

Reading the router against two more everyday actions found two false positives before any capture existed:

- **Opening the browser.** `npm start --open`, Vite and create-react-app use the `open` package, which on Windows starts `powershell -EncodedCommand` with `Start "http://localhost:3000"` encoded inside. To the router that was encoded PowerShell from node: 30, over the threshold, on every dev-server start.
- **`git clone` from an npm script.** `cmd.exe` plus a URL scored 35.

The fix keeps the framework's rule: score down, never exclude, and only for the benign *shape*. The router now decodes `-EncodedCommand` and inspects the decoded text alongside the command line, so a browser open to a loopback address with nothing else in it cancels its own encoded and URL points, while an encoded cradle is now scored as a cradle rather than only as "encoded" (FIX-11). A `git` / `npm` fetch whose every URL is a known code host cancels the URL points; `raw.githubusercontent.com` is deliberately not on that list. Any cradle, LOLBin, pipe or chained command anywhere cancels the discount. Both actions are now steps B6 and B7 of the benign emulation, so the benign capture proves the fix instead of this note claiming it.

## 4. Closing gaps with the Cousin Pack

Each variant the core sensors could not see got its own sensor with its own minimum truth, in one telemetry domain:

| Variant | Why the core missed it | Cousin | Minimum truth |
|---|---|---|---|
| Run-key persistence | no process event to anchor on | `nodejs_persistence_autostart` | an autostart value launches a .js file |
| Staging / Startup drop | file activity, not process | `nodejs_file_dropper` | node writes an executable or script type |
| npm postinstall | runs before the app exists | `npm_install_script_abuse` | the package manager's child reaches the network |
| Electron run as node | the binary is a signed editor | `electron_as_node_execution` | the app is launched with a script argument |

The Electron case is the one worth remembering: the environment variable that enables the abuse is invisible to Defender, which made it look like a pure boundary. The *launch shape* is not invisible: an editor started with a script file as its argument is something its own helper processes never do. Most of the boundary became coverage by asking what the abuse cannot avoid, rather than what it is called.

## 5. Making the lab tell the truth

- **Destination names.** Sysmon records a reverse-DNS name on network events; Defender records the name the process asked for. Without fixing that, the lab could never test "node talking to a blockchain RPC endpoint" or "npm talking to its registry". The converter now names each connection from the same process's own DNS query, as Defender does.
- **Timeouts.** The first emulation hung on a network call with no timeout and the VM had to be restarted. Every network call now gives up after 10 seconds and every child after 30, and the script prints each step.

## 6. The certutil block: a LOLBin is abuse of a feature, not an exploit

During the first capture the VM refused one step: `spawn EPERM` when node launched `cmd.exe` to run `certutil -urlcache -f http://...`. The same node process had just started `cmd.exe` three times without trouble, so the block was not about the program; something inspected the **command line** and refused that specific use.

A second observation sharpened it: the same `certutil -urlcache` command **ran normally when typed at an administrator's prompt on the same VM**. So the block was not on the binary, and not on the command alone, but on the **lineage**: an unusual runtime in a temp folder starting a LOLBin download. The protection judged the parent chain, exactly as the router does.

That is the distinction this threat turns on:

- **An exploit** abuses a bug to make software do what it was never designed to do.
- **A LOLBin** abuses a feature: `certutil` downloading a file is certutil working as designed. Nothing is patched, and most estates cannot simply block the binary because administrators and installers need it.

So the control that stopped it is a *policy on how a trusted tool is used*. Once a setting on the VM was switched off for the run, the step went through and was captured. Two consequences for the detections:

1. **Detection anchors on use, not on the binary.** The router alerts on certutil appearing on a node child's command line with a URL. A blocked attempt and an allowed one look the same at that point, so the rule works whether or not the estate has that protection on.
2. **Every capture records the protection state.** The capture notes say which protection was disabled for the run, so anyone reusing the dataset knows the conditions it was recorded under.

**`node_lab_v1` was recorded with that protection active:** the certutil step was refused, so this capture proves the IEX cradle and the encoded PowerShell, not the LOLBin step. A re-capture with the protection disabled (and the setting named here) will add certutil back to the router's test.

## 7. What the tests will settle

Three captures test each detection three ways: does it fire on the main path (`node_lab_v1`), does it survive the variants (`node_variants_v1`), and does it stay silent on normal developer use (`node_benign_v1`). The README's variant coverage matrix fills in from those results, and anything that fails goes back through the same loop: rule bug, harness bug, or a documented boundary.
