# Forensics: Node.js Runtime Abuse

What the threat leaves on a host, where to find it, and what each artefact proves. The [telemetry](../telemetry/) captured from the lab emulation contains every Sysmon artefact listed here, so this page doubles as a practice dataset.

## Artefacts

| Artefact | Where | Sysmon | Defender table | Proves |
|---|---|---|---|---|
| Runtime in a writable folder | `%AppData%`, `%LocalAppData%`, `%Temp%`, `Downloads` | EID 1 `Image`, EID 11 file create | `DeviceProcessEvents.FolderPath`, `DeviceFileEvents` | node was brought onto the host, not installed |
| The `.js` payload | Same folder, or the path on node's command line | EID 11 (written), EID 1 `CommandLine` (run) | `DeviceFileEvents`, `DeviceProcessEvents.ProcessCommandLine` | what ran: collect it, it is the malware |
| Launch chain | node's parent and grandparent | EID 1 `ParentImage`, `ParentCommandLine` | `InitiatingProcessFileName`, `InitiatingProcessParentFileName` | how it was delivered: script host, LNK (explorer), pasted command |
| Child processes | `cmd.exe /d /s /c "..."` (Windows), `/bin/sh -c "..."` (Linux) | EID 1 with `ParentImage` = node | `DeviceProcessEvents` | what the attacker did with the foothold |
| Network destinations | IP, port, and (in Defender) the URL / SNI | EID 3 (IP, port; hostname is reverse DNS only), EID 22 DNS query | `DeviceNetworkEvents.RemoteIP/RemoteUrl` | who the operator is; blockchain RPC hosts point at EtherHiding-style C2 resolution |
| Persistence | Run keys, TaskCache, services pointing at node + script | EID 12/13 | `DeviceRegistryEvents` | how it survives a reboot |
| Renamed runtime | Any name, same PE metadata | EID 1 `OriginalFileName`, `Product` | `ProcessVersionInfoOriginalFileName`, `ProcessVersionInfoProductName` | masquerading |

## Telemetry fidelity: Sysmon vs Defender

- **Destination names.** Sysmon EID 3 records the reverse-DNS name of an IP, not the domain node asked for. Defender's `RemoteUrl` carries the real name. In the lab, blockchain RPC calls therefore show as IPs; correlate with EID 22 DNS queries to recover the names.
- **Connection volume.** One TCP connection is one event in both. The emulation opens a new connection per poll (`agent: false`) so the beacon is visible; malware that keeps one socket open shows as a single long connection, which timing analysis cannot see.
- **Enrichment.** The converter fills each network, file and registry row with the acting process's hashes, version info, command line and parent from its process-create event (`tools/mde_mapping.py`), as Defender does.

## Triage order on a suspect host

1. **Process tree** of every node execution in the window (hunting query 5): parent, grandparent, command line.
2. **Collect the script** named on node's command line, and the whole runtime folder. Hash both; check the hash estate-wide.
3. **What dropped them:** `DeviceFileEvents` for that folder, earliest writes first.
4. **What node did:** children, network destinations, files written.
5. **Persistence:** autostart values that reference node or the script.
6. **Scope:** the script name, runtime path and destinations across the estate.

## Working with the lab dataset

```powershell
# load this threat's telemetry into your local Defender-shaped tenant, then hunt in the ADX web UI
powershell -ExecutionPolicy Bypass -File lab.ps1 -Load
```

The raw JSON in `telemetry/` is unmodified `Export-SysmonWindow.ps1` output: one object per Sysmon event with `EventId`, `TimeCreated`, `Computer` and the named `EventData` fields. Its `.yml` alongside records the window, host, event counts and SHA-256, so any analysis can be reproduced against the exact same evidence.
