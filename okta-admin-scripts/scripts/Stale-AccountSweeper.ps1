<#
.SYNOPSIS
    Finds dormant Okta user accounts; deactivation is dry-run unless forced.

.DESCRIPTION
    ACTIVE users whose lastLogin is older than -Days are flagged DORMANT.
    ACTIVE users that never logged in and were created more than -Days ago are
    flagged NEVER_LOGGED_IN (a separate category). Recently created accounts
    that never logged in are left alone.

    DRY-RUN BY DEFAULT: the script only reports. Deactivation happens only
    when BOTH -Disable AND -Confirm are passed, via
    POST /api/v1/users/{id}/lifecycle/deactivate. The Action column shows
    "would deactivate" for a dry run, "deactivated" for a performed
    deactivation, or a failure message.

.PARAMETER Days
    Dormancy threshold in days. Default 90.

.PARAMETER Limit
    Maximum number of flagged accounts to report/process. 0 (default) = all.

.PARAMETER Disable
    With -Confirm, actually deactivates the flagged accounts.

.PARAMETER Confirm
    Safety switch. Required together with -Disable to perform deactivation.

.PARAMETER Json
    Emit the report as JSON instead of a table.

.PARAMETER Output
    Write the report to the given file path. CSV by default, JSON with -Json.

.EXAMPLE
    pwsh ./Stale-AccountSweeper.ps1 -Days 90
    Reports dormant ACTIVE users without changing anything (dry run).

.EXAMPLE
    pwsh ./Stale-AccountSweeper.ps1 -Days 180 -Limit 10
    Dry-run report of up to 10 users dormant for 180+ days.

.EXAMPLE
    pwsh ./Stale-AccountSweeper.ps1 -Days 90 -Disable -Confirm -Output sweep.csv
    Deactivates dormant accounts and writes the CSV report to sweep.csv.
#>

param(
    [int]$Days = 90,
    [int]$Limit = 0,
    [switch]$Disable,
    [switch]$Confirm,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

$doDisable = $Disable -and $Confirm
$now = (Get-Date).ToUniversalTime()
$cutoff = $now.AddDays(-$Days)

$rows = @()
$users = @(Get-OktaUsers -Client $client -Status 'ACTIVE')
foreach ($u in $users) {
    $lastLoginRaw = $u.lastLogin
    $created = [datetime]$u.created
    $category = $null
    $daysDormant = $null
    $lastLoginDisplay = $null

    $neverLoggedIn = ($null -eq $lastLoginRaw) -or ('' -eq "$lastLoginRaw")
    if ($neverLoggedIn) {
        if ($created -lt $cutoff) {
            $category = 'NEVER_LOGGED_IN'
            $daysDormant = [int](($now - $created).TotalDays)
            $lastLoginDisplay = 'never'
        }
    } else {
        $lastLogin = [datetime]$lastLoginRaw
        if ($lastLogin -lt $cutoff) {
            $category = 'DORMANT'
            $daysDormant = [int](($now - $lastLogin).TotalDays)
            $lastLoginDisplay = $lastLogin.ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    }
    if (-not $category) { continue }

    $action = 'would deactivate'
    if ($doDisable) {
        try {
            Invoke-OktaRequest -Client $client -Method POST -Path "/api/v1/users/$($u.id)/lifecycle/deactivate" | Out-Null
            $action = 'deactivated'
        } catch {
            $action = "failed: $($_.Exception.Message)"
        }
    }

    $rows += [pscustomobject]@{
        Login       = $u.profile.login
        Name        = (@($u.profile.firstName, $u.profile.lastName) -join ' ').Trim()
        LastLogin   = $lastLoginDisplay
        DaysDormant = $daysDormant
        Category    = $category
        Action      = $action
    }
}

if ($Limit -gt 0 -and $rows.Count -gt $Limit) { $rows = $rows[0..($Limit - 1)] }

if ($Json) {
    $payload = $rows | ConvertTo-Json -Depth 10
    if ($payload) { Write-Output $payload }
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} else {
    $rows | Format-Table -AutoSize
    if ($Output) { $rows | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8 }
}
