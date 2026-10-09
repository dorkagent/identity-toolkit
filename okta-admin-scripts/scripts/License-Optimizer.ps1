#Requires -Version 7.0
<#
.SYNOPSIS
    Rough per-app license waste estimate, plus users sharing an email (read-only).

.DESCRIPTION
    Read-only. Makes one pass over System Log SSO events
    (user.authentication.sso; at most 90 days, which is all Okta keeps) within the last
    -LookbackDays, tallying logins per app by matching event target ids
    against known app ids. Apps with zero logins but at least one assignment
    are waste candidates.

    Estimated monthly waste = unused seats * per-seat cost. Per-seat cost is
    read from an optional -CostFile JSON of the form {"appLabel": monthlyCostPerSeat}
    and falls back to -CostDefault per seat. Candidates are ranked by
    estimated monthly waste, highest first.

    Separately, ACTIVE users sharing a lowercased email are listed (Okta
    logins are unique, so there is no login check).

    App-level only: apps that never emit user.authentication.sso (bookmarks,
    provisioning-only apps, some OIDC flows) always look unused.

.PARAMETER LookbackDays
    System Log window in days. Default 90.

.PARAMETER Limit
    Maximum number of apps to analyze. 0 (default) = all apps.

.PARAMETER CostFile
    Path to a JSON file mapping app labels to monthly cost per seat,
    e.g. {"Workday": 25, "Zoom": 12}. Optional.

.PARAMETER CostDefault
    Monthly cost per seat used when an app label is absent from -CostFile.
    Default 10.

.PARAMETER Json
    Emit the report (waste candidates and duplicates) as JSON instead of tables.

.PARAMETER Output
    Write the report to the given file path. CSV of the waste table by
    default; JSON (waste + duplicates) with -Json.

.EXAMPLE
    pwsh ./License-Optimizer.ps1
    Reports waste candidates and duplicate identities over the last 90 days.

.EXAMPLE
    pwsh ./License-Optimizer.ps1 -LookbackDays 30 -CostFile costs.json -Output waste.json -Json
    Uses the cost file for the last 30 days and writes a JSON report.

.EXAMPLE
    pwsh ./License-Optimizer.ps1 -Limit 20 -Output waste.csv
    Analyzes up to 20 apps and writes the ranked waste CSV.
#>

param(
    [int]$LookbackDays = 90,
    [int]$Limit = 0,
    [string]$CostFile,
    [int]$CostDefault = 10,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

if ($LookbackDays -gt 90) { Write-Warning 'The System Log keeps 90 days; using 90.'; $LookbackDays = 90 }
$cutoffIso = [datetime]::UtcNow.AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

$apps = @(Get-OktaApps -Client $client)
if ($Limit -gt 0 -and $apps.Count -gt $Limit) { $apps = $apps[0..($Limit - 1)] }

$costTable = @{}
if ($CostFile -and (Test-Path $CostFile)) {
    $costJson = Get-Content -Path $CostFile -Raw | ConvertFrom-Json
    foreach ($prop in $costJson.PSObject.Properties) {
        try {
            $costTable[$prop.Name] = [decimal]$prop.Value
        } catch {
            $costTable[$prop.Name] = $CostDefault
        }
    }
}

$appIds = @{}
foreach ($a in $apps) { $appIds[$a.id] = $true }

# One pass over System Log login events; tally per app id.
$loginCounts = @{}
# user.session.start targets the user, not an app, so only SSO events count.
$filter = 'eventType eq "user.authentication.sso"'
$events = @(Get-OktaLogs -Client $client -Filter $filter -Since $cutoffIso)
foreach ($e in $events) {
    foreach ($t in @($e.target)) {
        if (($null -ne $t) -and $appIds.ContainsKey($t.id)) {
            if ($loginCounts.ContainsKey($t.id)) {
                $loginCounts[$t.id] = $loginCounts[$t.id] + 1
            } else {
                $loginCounts[$t.id] = 1
            }
        }
    }
}

# Waste candidates: zero logins in the window but at least one assignment.
$waste = @()
foreach ($a in $apps) {
    $logins = 0
    if ($loginCounts.ContainsKey($a.id)) { $logins = $loginCounts[$a.id] }
    if ($logins -gt 0) { continue }
    $assigned = @(Get-OktaAppUsers -Client $client -AppId $a.id).Count
    if ($assigned -le 0) { continue }
    $costPerSeat = $CostDefault
    if ($costTable.ContainsKey($a.label)) { $costPerSeat = $costTable[$a.label] }
    $waste += [pscustomobject]@{
        App             = $a.label
        UnusedSeats     = $assigned
        CostPerSeat     = $costPerSeat
        EstMonthlyWaste = $assigned * $costPerSeat
    }
}
$waste = @($waste | Sort-Object -Property EstMonthlyWaste -Descending)

# Shared email addresses among ACTIVE users.
$byEmail = @{}
foreach ($u in Get-OktaUsers -Client $client -Status 'ACTIVE') {
    $emailKey = "$($u.profile.email)".ToLowerInvariant()
    if (-not $emailKey) { continue }
    if (-not $byEmail.ContainsKey($emailKey)) { $byEmail[$emailKey] = @() }
    $byEmail[$emailKey] += [string]$u.profile.login
}
$dups = @(foreach ($key in $byEmail.Keys) {
    if ($byEmail[$key].Count -ge 2) {
        [pscustomobject]@{ Email = $key; Count = $byEmail[$key].Count; Logins = ($byEmail[$key] -join '; ') }
    }
})

if ($Json) {
    $payload = [pscustomobject]@{ Waste = $waste; Duplicates = $dups } | ConvertTo-Json -Depth 10
    if ($payload) { Write-Output $payload }
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} else {
    $waste | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
    Write-Output ''
    Write-Output 'Active users sharing an email address:'
    $dups | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
    if ($Output) { $waste | Export-OktaCsv -Path $Output }
}
