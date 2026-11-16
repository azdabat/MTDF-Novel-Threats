# Hunting: Node.js Runtime Abuse

Hunts complement the detections: they are broad, run on demand, and are meant to be read by a person. Every query here runs unchanged in Defender Advanced Hunting, in Sentinel (MDE connector), and in the local lab after `lab.ps1 -Load` has loaded this threat's telemetry into the tables.

## 1. Where does node run in this estate?

Establish the baseline first: which devices run node at all, from where, and launched by what. A node runtime on a device that has never run one is the strongest single signal in this threat.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node") or ProcessVersionInfoOriginalFileName =~ "node.exe"
| extend RuntimeDir = tostring(split(FolderPath, @"\node")[0])
| summarize Runs = count(), Devices = dcount(DeviceId), Parents = make_set(InitiatingProcessFileName, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RuntimeDir
| order by Devices asc, Runs asc
```

Runtimes under `AppData`, `Temp` or `Downloads` on one or two devices are the first thing to read.

## 2. Everything node started (the collector, as a hunt)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| summarize Count = count(), Devices = dcount(DeviceId), Example = any(ProcessCommandLine)
    by Child = FileName, Parent = InitiatingProcessFileName
| order by Devices asc
```

Rare children (`certutil`, `whoami`, `powershell -e`, `curl`) on few devices are the leads. On Windows, also expand `cmd.exe` children by command line: that is where the real tool is.

## 3. Who does node talk to?

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where not(ipv4_is_private(RemoteIP))
| summarize Connections = count(), Devices = dcount(DeviceId), Ports = make_set(RemotePort, 5),
            Runtimes = make_set(InitiatingProcessFolderPath, 5) by Dest = iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)
| order by Devices asc, Connections desc
```

Destinations reached by node on one device that are not package registries or code hosts are the leads. Any blockchain RPC host (Infura, Alchemy, PublicNode, `bsc-dataseed`, `trongrid`) from a non-developer device is worth a look on its own.

## 4. Node in autostart locations

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\Schedule\TaskCache", @"\Services\")
| where RegistryValueData has "node" and RegistryValueData has ".js"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

This is also the starting point for the planned `NodeJS_Persistence` sensor.

## 5. One device, one timeline

When any of the above finds something, build the full node timeline on that device:

```kql
let dev = "VM-Lab";                 // the device to examine
let t0 = datetime(2026-11-16 08:00); let t1 = datetime(2026-11-16 09:00);
union
  (DeviceProcessEvents | where InitiatingProcessFileName in~ ("node.exe","node") or FileName in~ ("node.exe","node")
     | project Timestamp, What = "process", Detail = strcat(InitiatingProcessFileName, " -> ", FileName, "  ", ProcessCommandLine)),
  (DeviceNetworkEvents | where InitiatingProcessFileName in~ ("node.exe","node")
     | project Timestamp, What = "network", Detail = strcat(RemoteIP, ":", RemotePort, " ", RemoteUrl)),
  (DeviceFileEvents | where InitiatingProcessFileName in~ ("node.exe","node")
     | project Timestamp, What = "file", Detail = strcat(ActionType, " ", FolderPath))
| where Timestamp between (t0 .. t1)
| order by Timestamp asc
```

See [forensics.md](forensics.md) for what each artefact proves.

---

# Hunting Node.js threats in general

The five hunts above follow one incident. The programme below covers the whole Node.js attack surface, one hunt per variant. Each hunt is the broad, human-read version of a detection: run it first, read what it finds, then promote it (see the table at the end).

## 6. Node under another name

A renamed runtime keeps its PE metadata. Any process that *is* node but is not *called* node:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName =~ "node.exe" or ProcessVersionInfoProductName =~ "Node.js"
| where FileName !in~ ("node.exe", "node")
| summarize Runs = count(), Devices = dcount(DeviceId), Paths = make_set(FolderPath, 10),
            Parents = make_set(InitiatingProcessFileName, 10) by FileName
```

Legitimate results are bundled apps (`pkg` / `nexe` builds of internal tools). Anything in Downloads or Temp is a lead.

## 7. Node writing executables

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe", "node") or InitiatingProcessVersionInfoOriginalFileName =~ "node.exe"
| where FileName matches regex @"(?i)\.(exe|dll|scr|ps1|bat|cmd|vbs|hta|lnk|msi)$"
| where FolderPath !has @"\node_modules\" and FolderPath !has @"\npm-cache\"
| summarize Files = make_set(FileName, 20), Devices = dcount(DeviceId) by Folder = tostring(split(FolderPath, FileName)[0])
| order by Devices asc
```

## 8. Autostart entries that run JavaScript

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\Winlogon", @"\Services\")
| where RegistryValueData matches regex @"(?i)\.(c|m)?js\b"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## 9. Electron apps started with a script

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("code.exe", "cursor.exe", "slack.exe", "discord.exe", "teams.exe", "obsidian.exe", "notion.exe")
| where ProcessCommandLine !has "--type=" and ProcessCommandLine matches regex @"(?i)\.(c|m)?js\b"
| where ProcessCommandLine !has @"\resources\app"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 10. What install scripts actually run

Every child of a package manager across the estate, ranked by rarity. This is the supply-chain baseline: a new, rare child that reaches the network is the lead.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where InitiatingProcessCommandLine has_any ("npm-cli.js", "yarn.js", "yarn.cjs", "pnpm.cjs")
| summarize Devices = dcount(DeviceId), Example = any(ProcessCommandLine) by Child = FileName,
            Shape = tostring(extract(@"^(\S+\s+\S+\s+\S+)", 1, ProcessCommandLine))
| order by Devices asc
```

## 11. Who talks to blockchain RPC endpoints

Not only node: any process resolving smart-contract data from a workstation deserves a look.

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("infura.io", "alchemy.com", "quiknode.pro", "ankr.com", "publicnode.com",
                           "llamarpc.com", "drpc.org", "cloudflare-eth.com", "bsc-dataseed", "binance.org", "trongrid.io")
| summarize Connections = count(), Devices = dcount(DeviceId), Hosts = make_set(RemoteUrl, 10)
    by Process = InitiatingProcessFileName, ProcessPath = InitiatingProcessFolderPath
| order by Devices asc
```

## From hunt to rule

A hunt becomes a detection once its results have a minimum truth that is rare in this estate and a noise model you can write down.

| Hunt | Became | Minimum truth it settled on |
|---|---|---|
| 1. Where node runs | `nodejs_loader_execution` | runtime or script in a user-writable path |
| 2. Everything node started | `nodejs_child_process_atomic` → `nodejs_child_process_router` | node spawns a child (index), with primitives (triage) |
| 3. Who node talks to, 11. Blockchain RPC | `nodejs_outbound_c2` | node connects out to a public address |
| 4. Node in autostart, 8. Autostart running JavaScript | `nodejs_persistence_autostart` | an autostart value launches a .js file |
| 6. Node under another name | metadata matching in the loader, collector and router | PE metadata says node.exe |
| 7. Node writing executables | `nodejs_file_dropper` | node writes an executable or script type |
| 9. Electron started with a script | `electron_as_node_execution` | an Electron binary launched with a script argument |
| 10. What install scripts run | `npm_install_script_abuse` | a package manager's child reaches the network, decodes or uses a LOLBin |
