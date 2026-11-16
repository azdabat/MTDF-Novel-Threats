# Lab VM

One Windows VM records every emulation in this repository. Set it up once.

## 1. Before anything: snapshot

Take a VirtualBox snapshot of the clean VM (**Machine → Take Snapshot**, name it `clean`). After each emulation, restore it, so every capture starts from the same state.

## 2. Sysmon, logging everything

In an **admin** PowerShell on the VM, in the folder holding `sysmonconfig-mtdf-lab.xml`:

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath Sysmon -Force
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig-mtdf-lab.xml
```

Already have Sysmon with another config? Switch it: `.\Sysmon\Sysmon64.exe -c sysmonconfig-mtdf-lab.xml`.
Check it works: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5`.

`sysmonconfig-mtdf-lab.xml` logs every process, network connection, file creation, registry change, DNS query and WMI event, plus access to LSASS. That is deliberately unfiltered: a production config excludes noise, and an exclusion is exactly what makes an emulation silently produce nothing.

## 3. Antivirus during an emulation

The VM's own Defender may refuse a step (`spawn EPERM`, or a blocked file write) even with real-time protection off: in the first Node.js run, only the command line containing `certutil -urlcache` was refused at process creation, while the other children of the same node process ran. A protection that inspects command lines did that, not a per-program setting. That is proof the behaviour is real, but it also leaves a hole in the capture. For a complete capture, turn real-time protection off for the run, **on the lab VM only**:

**Windows Security → Virus & threat protection → Manage settings → Real-time protection: Off.** Run the emulation, then switch it back on. (Windows turns it back on by itself after a while.) Note in the capture's `--notes` that AV was off.

## 4. Per-threat prerequisites

Each threat's `emulation/README.md` lists what that emulation needs (for example Node.js for `nodejs-runtime-abuse`).

## 5. Getting the capture off the VM

Every emulation writes its capture as JSON next to the script. Copy it to your main machine through a VirtualBox shared folder (**Devices → Shared Folders**), or drag and drop with **Devices → Drag and Drop → Bidirectional** enabled.

## Safety rules for emulations

- Emulations reproduce **behaviour**, never exploits or real malware. Downloads point at `127.0.0.1` ports where nothing listens; encoded commands decode to `whoami`; network calls are read-only requests to public services.
- Run them only on this VM, never on a work-managed device.
- The VM's own Defender may alert on the behaviour. That is expected and is evidence the behaviour is real.
