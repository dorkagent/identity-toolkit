<#
.SYNOPSIS
    Monitors Okta System Log for break-glass (emergency admin) account sign-in activity. (DHQ-84, read-only)

.DESCRIPTION
    Resolves each break-glass login via Get-OktaUserByLogin, then scans the Okta
    System Log for sign-in related events (user.session.start and
    policy.evaluate_sign_on) within the lookback window. Events are matched to
    the break-glass accounts client-side by actor.id and classified as:

      user.session.start                                   -> SUCCESS
      policy.evaluate_sign_on with outcome.result FAILURE -> FAILED
      policy.evaluate_sign_on otherwise                   -> POLICY_OK

    Use -Watch to poll continuously and print new events as they arrive, with
    timestamp, IP address, and geolocation (city/country).

    Authentication comes from the OKTA_DOMAIN / OKTA_API_TOKEN environment
    variables only. No usernames are hardcoded; pass them via -Accounts.

.PARAMETER Accounts
    Comma-separated list of break-glass account logins to monitor. Required.

.PARAMETER LookbackHours
    How many hours back to scan in one-shot mode (also used for the first
    -Watch poll). Default 24.

.PARAMETER Watch
    Poll continuously for new events instead of running a one-shot scan.

.PARAMETER Interval
    Seconds between polls in -Watch mode. Default 300.

.PARAMETER Json
    Emit the report as JSON instead of a table.

.PARAMETER Output
    Write the report to this file path (JSON with -Json, CSV otherwise).
    In -Watch mode, new rows are appended as they arrive (JSON Lines for -Json).

.EXAMPLE
    .\Break-GlassMonitor.ps1 -Accounts "bg-admin1,bg-admin2"

    One-shot scan of the last 24 hours for the two break-glass accounts.

.EXAMPLE
    .\Break-GlassMonitor.ps1 -Accounts "bg-admin1" -Watch -Interval 60 -Output .\bg-events.csv

    Watch mode: poll every 60 seconds and append new events to bg-events.csv.

.EXAMPLE
    .\Break-GlassMonitor.ps1 -Accounts "bg-admin1,bg-admin2" -LookbackHours 72 -Json -Output .\bg-report.json

    Scan the last 72 hours and write a JSON report to bg-report.json.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Accounts,
    [int]$LookbackHours = 24,
    [switch]$Watch,
    [int]$Interval = 300,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

$ErrorActionPreference = 'Stop'

function Get-UtcIso8601 {
    param([datetime]$When)
    return $When.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function New-BreakGlassRow {
    param($LogEvent, [string]$Login)
    $ip = ""
    $city = ""
    $country = ""
    if ($LogEvent.client) {
        if ($LogEvent.client.ipAddress) { $ip = [string]$LogEvent.client.ipAddress }
        $geo = $LogEvent.client.geographicalContext
        if ($geo) {
            if ($geo.city) { $city = [string]$geo.city }
            if ($geo.country) { $country = [string]$geo.country }
        }
    }
    $locParts = @()
    if ($city) { $locParts += $city }
    if ($country) { $locParts += $country }
    $location = $locParts -join ", "

    $result = "UNKNOWN"
    if ($LogEvent.eventType -eq "user.session.start") {
        $result = "SUCCESS"
    } elseif ($LogEvent.eventType -eq "policy.evaluate_sign_on") {
        if ($LogEvent.outcome -and $LogEvent.outcome.result -eq "FAILURE") {
            $result = "FAILED"
        } else {
            $result = "POLICY_OK"
        }
    }

    return [pscustomobject]@{
        Time     = [string]$LogEvent.published
        Account  = $Login
        Result   = $result
        IP       = $ip
        Location = $location
        Event    = [string]$LogEvent.eventType
    }
}

function Write-RowsToFile {
    param([array]$Rows, [switch]$Append)
    if (-not $Rows -or $Rows.Count -eq 0) { return }
    if ($Json) {
        if ($Append) {
            foreach ($row in $Rows) {
                ($row | ConvertTo-Json -Depth 10 -Compress) | Out-File -FilePath $Output -Append -Encoding utf8
            }
        } else {
            ($Rows | ConvertTo-Json -Depth 10) | Out-File -FilePath $Output -Encoding utf8
        }
    } else {
        if ($Append -and (Test-Path $Output)) {
            $Rows | Export-Csv -Path $Output -NoTypeInformation -Append
        } else {
            $Rows | Export-Csv -Path $Output -NoTypeInformation
        }
    }
}

function Show-Rows {
    param([array]$Rows)
    if ($Json) {
        $Rows | ConvertTo-Json -Depth 10
    } else {
        $Rows | Format-Table -AutoSize
    }
}

function Get-MatchingRows {
    param([string]$Since)
    $rows = @()
    $events = @(Get-OktaLogs -Client $client -Filter $script:logFilter -Since $Since)
    foreach ($e in $events) {
        $actorId = ""
        if ($e.actor -and $e.actor.id) { $actorId = [string]$e.actor.id }
        if ($script:idToLogin.ContainsKey($actorId)) {
            $rows += New-BreakGlassRow -Event $e -Login $script:idToLogin[$actorId]
        }
    }
    return $rows
}

# Resolve the break-glass accounts; never hardcode usernames.
$script:idToLogin = @{}
foreach ($login in ($Accounts -split ',')) {
    $login = $login.Trim()
    if (-not $login) { continue }
    $user = Get-OktaUserByLogin -Client $client -Login $login
    if (-not $user) {
        Write-Warning "Break-glass account not found: $login"
        continue
    }
    $script:idToLogin[[string]$user.id] = $login
}
if ($script:idToLogin.Count -eq 0) {
    throw "None of the -Accounts logins resolved to an Okta user."
}

$script:logFilter = 'eventType eq "user.session.start" or eventType eq "policy.evaluate_sign_on"'

if (-not $Watch) {
    # One-shot scan.
    $cutoff = Get-UtcIso8601 -When ((Get-Date).AddHours(-$LookbackHours))
    $rows = @(Get-MatchingRows -Since $cutoff)
    if ($rows.Count -eq 0) {
        Write-Output "No break-glass sign-in activity in the last $LookbackHours hour(s)."
    } else {
        Show-Rows -Rows $rows
        if ($Output) { Write-RowsToFile -Rows $rows }
    }
    return
}

# Watch mode: poll for new events since the last poll.
$since = Get-UtcIso8601 -When ((Get-Date).AddHours(-$LookbackHours))
$seen = @{}
Write-Output "Watching $($script:idToLogin.Count) break-glass account(s) every $Interval second(s). Press Ctrl+C to stop."
while ($true) {
    $rows = @(Get-MatchingRows -Since $since)
    $newRows = @()
    $maxPublished = $since
    foreach ($row in $rows) {
        $key = "$($row.Time)|$($row.Account)|$($row.Event)|$($row.IP)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $newRows += $row
        }
        if ($row.Time -gt $maxPublished) { $maxPublished = $row.Time }
    }
    foreach ($row in $newRows) {
        Write-Output ("[{0}] {1} {2} ip={3} loc={4}" -f $row.Time, $row.Account, $row.Result, $row.IP, $row.Location)
    }
    if ($newRows.Count -gt 0) {
        if ($Json) {
            foreach ($row in $newRows) { $row | ConvertTo-Json -Depth 10 -Compress }
        } else {
            $newRows | Format-Table -AutoSize
        }
        if ($Output) { Write-RowsToFile -Rows $newRows -Append }
    }
    $since = $maxPublished
    Start-Sleep -Seconds $Interval
}
