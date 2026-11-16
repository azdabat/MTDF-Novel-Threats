<#
  push_to_github.ps1 - first upload to a new, EMPTY GitHub repository.
      powershell -ExecutionPolicy Bypass -File push_to_github.ps1 -User azdabat
#>
param([Parameter(Mandatory = $true)][string]$User, [string]$Repo = "MTDF-Novel-Threats")
Set-Location $PSScriptRoot
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Host "Install Git: https://git-scm.com/download/win" -ForegroundColor Red; exit 1 }
if (-not (Test-Path .git)) { git init -b main | Out-Null }
if (-not (git config user.name))  { git config user.name $User }
if (-not (git config user.email)) { git config user.email "$User@users.noreply.github.com" }
git add -A
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) { git commit -m "MTDF Novel Threats: threat format, pipeline, Node.js runtime abuse" | Out-Null }
$url = "https://github.com/$User/$Repo.git"
$existing = git remote 2>$null
if ($existing -contains "origin") { git remote set-url origin $url } else { git remote add origin $url }
Write-Host "Pushing to $url (a GitHub sign-in window may open)..." -ForegroundColor Cyan
git push -u origin main
if ($LASTEXITCODE -eq 0) { Write-Host "Done: https://github.com/$User/$Repo/actions" -ForegroundColor Green }
else { Write-Host "Push refused. If the GitHub repo is not empty, run:  git push -u origin main --force" -ForegroundColor Yellow }
