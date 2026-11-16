<#
  publish.ps1 - sync, validate, commit and push. GitHub Actions then re-runs the whole pipeline.
      powershell -ExecutionPolicy Bypass -File publish.ps1 -Message "Add <threat>"
      powershell -ExecutionPolicy Bypass -File publish.ps1 -Promote -Message "Promote passing tests"
#>
param([string]$Message = "Update threats", [switch]$Promote)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
git pull --rebase --autostash
if ($LASTEXITCODE -ne 0) { Write-Host "git pull failed - resolve it, then run again." -ForegroundColor Red; exit 1 }
if ($Promote) { python tools\promote.py --apply; if ($LASTEXITCODE -ne 0) { exit 1 } }
python tools\validate_threats.py
if ($LASTEXITCODE -ne 0) { Write-Host "Format errors - fix them before publishing." -ForegroundColor Red; exit 1 }
python tools\lint_kql.py threats --no-port
if ($LASTEXITCODE -ne 0) { Write-Host "Lint errors - fix them before publishing." -ForegroundColor Red; exit 1 }
python tools\build_threat_docs.py
git add -A
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) { Write-Host "Nothing to commit."; exit 0 }
git commit -m $Message
git push
Write-Host "Pushed. Watch the run: Actions tab on GitHub." -ForegroundColor Green
