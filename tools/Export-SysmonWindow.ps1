<#
.SYNOPSIS
    Export Microsoft-Windows-Sysmon/Operational events in a time window to JSON,
    with EventData flattened to named fields (ready for sysmon_to_mde.py).

.DESCRIPTION
    Runs on the victim VM (Windows PowerShell 5.1 or PowerShell 7).
    Emits a JSON array of:
      { EventId, TimeCreated(ISO/UTC), Computer, RecordId, EventData{ named fields } }

.EXAMPLE
    # Everything Sysmon logged in the last 10 minutes
    .\Export-SysmonWindow.ps1 -LastMinutes 10 -Out lsass_atomic_comsvcs.raw.json

.EXAMPLE
    # An explicit window, only the EventIDs you care about
    .\Export-SysmonWindow.ps1 -Start '2026-11-09T14:00:00Z' -End '2026-11-09T14:12:00Z' -EventId 1,7,10,11,13
#>
[CmdletBinding(DefaultParameterSetName = 'Window')]
param(
    [Parameter(ParameterSetName = 'Last')]  [int]$LastMinutes,
    [Parameter(ParameterSetName = 'Window')][datetime]$Start,
    [Parameter(ParameterSetName = 'Window')][datetime]$End = (Get-Date),
    [int[]]$EventId,
    [string]$Out = "sysmon_export.json"
)

if ($PSCmdlet.ParameterSetName -eq 'Last') {
    $End   = Get-Date
    $Start = $End.AddMinutes(-1 * $LastMinutes)
}
if (-not $Start) { throw "Provide -LastMinutes, or -Start (with optional -End)." }

$filter = @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $Start
    EndTime   = $End
}
if ($EventId) { $filter['Id'] = $EventId }

$rows = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml()
    $data = [ordered]@{}
    foreach ($e in $x.Event.EventData.Data) { $data[$e.Name] = $e.'#text' }
    [pscustomobject]@{
        EventId     = [int]$_.Id
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        Computer    = $_.MachineName
        RecordId    = $_.RecordId
        EventData   = $data
    }
}

# Force a JSON array even for 0 or 1 rows (Windows PowerShell 5.1 has no -AsArray).
$arr  = @($rows)
$json = if ($arr.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $arr -Depth 8 }
Set-Content -Path $Out -Value $json -Encoding utf8

Write-Host ("Exported {0} events  [{1:u} .. {2:u}]  ->  {3}" -f $arr.Count, $Start.ToUniversalTime(), $End.ToUniversalTime(), $Out)
