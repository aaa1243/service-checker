# Self-test for CI (needs admin). Breaks the DPS service on purpose, checks the
# scanner flags it, runs the fix and checks it is running again.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $root 'ServiceChecker.ps1'
$out  = Join-Path $env:TEMP 'svc-selftest'
New-Item -ItemType Directory -Path $out -Force | Out-Null

function Invoke-Scan([string]$Name, [switch]$Fix) {
    $json = Join-Path $out ($Name + '.json')
    if ($Fix) { & powershell -NoProfile -ExecutionPolicy Bypass -File $tool -NoGui -Fix -Json $json -OutDir $out | Out-Host }
    else      { & powershell -NoProfile -ExecutionPolicy Bypass -File $tool -NoGui -Json $json -OutDir $out | Out-Host }
    if (-not (Test-Path $json)) { throw "Scan '$Name' wrote no JSON" }
    return (Get-Content $json -Raw | ConvertFrom-Json)
}
function Get-Row($Rows, [string]$Name) { return ($Rows | Where-Object { $_.Name -eq $Name } | Select-Object -First 1) }

Write-Host '=== 1. First scan ==='
$rows = Invoke-Scan 'first'
if (@($rows).Count -lt 12) { throw "Expected at least 12 rows, got $(@($rows).Count)" }
foreach ($n in 'EventLog', 'Schedule', 'PlugPlay') {
    $r = Get-Row $rows $n
    if ($null -eq $r -or $r.State -ne 'Running') { throw "$n should be found and running" }
}
if (@(Get-ChildItem $out -Filter 'scan_*.txt').Count -lt 1) { throw 'No scan report was written' }

Write-Host '=== 1b. Run from text, the way the one-liner does ==='
$json = Join-Path $out 'oneliner.json'
& powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Get-Content -Raw '$tool'))) -NoGui -Json '$json' -OutDir '$out'" | Out-Host
if (-not (Test-Path $json)) { throw 'Running from text wrote no JSON' }
$rows2 = Get-Content $json -Raw | ConvertFrom-Json
if (@($rows2).Count -lt 12) { throw "Running from text returned $(@($rows2).Count) rows, expected at least 12" }

Write-Host '=== 2. Break DPS on purpose ==='
Set-Service -Name DPS -StartupType Disabled
Stop-Service -Name DPS -Force
$rows = Invoke-Scan 'broken'
$dps = Get-Row $rows 'DPS'
if ($dps.Result -ne 'DISABLED' -or -not $dps.Fixable) { throw "DPS should be flagged DISABLED and fixable, got '$($dps.Result)'" }

Write-Host '=== 3. Fix ==='
$rows = Invoke-Scan 'fixed' -Fix
$dps = Get-Row $rows 'DPS'
if ($dps.State -ne 'Running') { throw "DPS should be running after the fix, state is '$($dps.State)'" }
if ($dps.StartType -notlike 'Automatic*') { throw "DPS start type should be Automatic after the fix, got '$($dps.StartType)'" }
if ($dps.Result -notin 'OK', 'RESTARTED') { throw "DPS result after the fix should be OK or RESTARTED, got '$($dps.Result)'" }
if (@(Get-ChildItem $out -Filter 'after_fix_*.txt').Count -lt 1) { throw 'No after_fix report was written' }

Write-Host 'SELF-TEST PASSED'
