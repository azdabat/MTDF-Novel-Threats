<#
  mtdf_node_benign.ps1 - a normal developer workflow with Node.js, for FALSE-POSITIVE testing. LAB VM ONLY.
      powershell -ExecutionPolicy Bypass -File mtdf_node_benign.ps1          (about 2 minutes)

  B1  npm init + npm install of a small real package (ms) in a project under Documents
  B2  node index.js: the app requires the package and fetches its metadata from registry.npmjs.org
  B3  npm run build, where the build script is "node -e ..." (the inline-eval flag)
  B4  npx cowsay: npm downloads and runs a CLI from its cache in %LocalAppData%\npm-cache
  B5  node -e one-liner from the shell
  The detections must stay SILENT on all of it. Exports Sysmon to node_benign_capture.json.
#>
$ErrorActionPreference = "Stop"
if (-not (Get-Service -Name Sysmon* -ErrorAction SilentlyContinue)) { Write-Host "Sysmon is not installed." -ForegroundColor Red; exit 1 }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Write-Host "Node.js not found - open a NEW PowerShell after installing it." -ForegroundColor Red; exit 1 }
$start = (Get-Date).AddSeconds(-5)
$proj = Join-Path $env:USERPROFILE "Documents\mtdf-devproj"
New-Item -ItemType Directory -Force -Path $proj | Out-Null
Push-Location $proj
Write-Host "B1 npm install..." -ForegroundColor Cyan
@'
{ "name": "mtdf-devproj", "version": "1.0.0", "private": true,
  "scripts": { "build": "node -e \"console.log('build ok')\"" } }
'@ | Set-Content package.json -Encoding ascii
npm install ms --silent 2>&1 | Out-Null
@'
const ms = require('ms'); const https = require('https');
const req = https.get('https://registry.npmjs.org/ms', res => { res.resume(); res.on('end', () => console.log('B2 fetched metadata; 2 days =', ms('2d'), 'ms')); });
req.setTimeout(10000, () => req.destroy()); req.on('error', () => console.log('B2 registry not reachable - carrying on'));
'@ | Set-Content index.js -Encoding utf8
Write-Host "B2 node index.js..." -ForegroundColor Cyan
node index.js
Write-Host "B3 npm run build..." -ForegroundColor Cyan
npm run build --silent
Write-Host "B4 npx cowsay..." -ForegroundColor Cyan
npx --yes cowsay "MTDF benign workflow" | Out-Null
Write-Host "B5 node -e..." -ForegroundColor Cyan
node -e "console.log(require('os').platform())" | Out-Null
Pop-Location
Start-Sleep -Seconds 5

$filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $start; EndTime = (Get-Date); Id = 1, 3, 11, 12, 13, 22 }
$rows = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml(); $data = [ordered]@{}
    foreach ($e in $x.Event.EventData.Data) { $data[$e.Name] = $e.'#text' }
    [pscustomobject]@{ EventId = [int]$_.Id; TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
                       Computer = $_.MachineName; RecordId = $_.RecordId; EventData = $data }
}
$arr = @($rows)
$out = Join-Path $PSScriptRoot "node_benign_capture.json"
Set-Content -Path $out -Value $(if ($arr.Count) { ConvertTo-Json -InputObject $arr -Depth 8 } else { '[]' }) -Encoding utf8
Remove-Item $proj -Recurse -Force -ErrorAction SilentlyContinue
$nodeRuns = @($arr | Where-Object { $_.EventId -eq 1 -and $_.EventData.Image -like '*\node.exe' }).Count
Write-Host ("Exported {0} Sysmon events -> {1}  ({2} node.exe starts)" -f $arr.Count, $out, $nodeRuns) -ForegroundColor Green
