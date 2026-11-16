<#
  lab.ps1 - the whole pipeline locally, against Kustainer on localhost:8080.

      powershell -ExecutionPolicy Bypass -File lab.ps1          # format, lint, compile, test, docs
      powershell -ExecutionPolicy Bypass -File lab.ps1 -Load    # also load every threat's telemetry into your
                                                                # Defender-shaped tables, for hunting in ADX
#>
param([switch]$Load)
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
$cluster = "http://localhost:8080"
function Step($n, $text) { Write-Host "`n[$n] $text" -ForegroundColor Cyan }

Step 1 "Format: every threat follows THREAT_FORMAT.md"
python tools\validate_threats.py
$format = $LASTEXITCODE

Step 2 "Lint: MTDF bug classes"
python tools\lint_kql.py threats --no-port
$lint = $LASTEXITCODE

Step 3 "Compile check with Microsoft's Kusto language service"
if (Get-Command node -ErrorAction SilentlyContinue) {
    if (-not (Test-Path tools\semantic\node_modules)) { npm install --prefix tools\semantic --no-audit --no-fund --silent }
    python tools\semantic_check.py
    $compile = $LASTEXITCODE
} else { Write-Host "    skipped: Node.js not installed (CI still runs it)" -ForegroundColor Yellow; $compile = 0 }

Step 4 "Is the Kusto engine (Docker) answering on $cluster ?"
$engine = $true
try {
    Invoke-RestMethod -Uri "$cluster/v1/rest/query" -Method Post -ContentType "application/json" `
        -Body '{"db":"NetDefaultDB","csl":"print ready=1"}' -TimeoutSec 15 | Out-Null
    Write-Host "    yes" -ForegroundColor Green
} catch { Write-Host "    NO - open Docker Desktop and start the kustainer container; skipping tests" -ForegroundColor Red; $engine = $false }

$tests = 0
if ($engine) {
    if ($Load) {
        Step "4a" "Shape the database like Defender and load every threat's telemetry"
        python tools\tenant_setup.py
        python tools\ingest_to_adx.py --all-detections
    }
    Step 5 "Run every test: each detection against the telemetry it must catch"
    python tools\run_tests.py --json docs\results.json
    $tests = $LASTEXITCODE
}

Step 6 "Generate threat READMEs, coverage matrices and ATT&CK layers"
python tools\build_threat_docs.py

Write-Host ""
if ($format -eq 0 -and $lint -eq 0 -and $compile -eq 0 -and $tests -eq 0 -and $engine) {
    Write-Host "PIPELINE GREEN. Next: powershell -ExecutionPolicy Bypass -File publish.ps1 -Message 'what changed'" -ForegroundColor Green
} else {
    Write-Host "Something needs a look - scroll up for ERROR / FAIL lines." -ForegroundColor Yellow
}
