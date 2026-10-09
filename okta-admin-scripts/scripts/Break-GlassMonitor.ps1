#Requires -Version 7.0
<#
.SYNOPSIS
    Reports sign-in activity on break-glass (emergency admin) accounts.

.DESCRIPTION
    Reads these System Log events and keeps the ones whose actor is one of
    the -Accounts (matched on actor.alternateId, the login, or actor.id):

      user.session.start                sign-in to Okta
      user.authentication.auth_via_mfa  MFA verification
      user.session.access_admin_app     opened the Admin Console
      policy.evaluate_sign_on           sign-on policy decision

    Each row shows the event's own outcome.result (SUCCESS, FAILURE, ALLOW,
    CHALLENGE...). A failed sign-in is a user.session.start with outcome
    FAILURE; for an account nobody should use, failures matter most.

    One-shot mode reads a bounded window. -Watch polls: each poll reads until
    Okta returns an empty page, prints new matches, then sleeps.

.PARAMETER Accounts
    Comma-separated break-glass logins.

.PARAMETER LookbackHours
    Hours to scan in one-shot mode. Default 24.

.PARAMETER Watch
    Keep polling for new events.

.PARAMETER Interval
    Seconds between polls with -Watch. Default 300.

.PARAMETER Json
    Print JSON instead of a table (JSON lines with -Watch).

.PARAMETER Output
    Also write rows to this file (JSON with -Json, otherwise CSV; appended with -Watch).

.EXAMPLE
    ./Break-GlassMonitor.ps1 -Accounts 'bg-admin1@example.com,bg-admin2@example.com'

.EXAMPLE
    ./Break-GlassMonitor.ps1 -Accounts 'bg-admin1@example.com' -Watch -Interval 60 -Output ./bg-events.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Accounts,
    [int]$LookbackHours = 24,
    [switch]$Watch,
    [int]$Interval = 300,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'
$client = New-OktaClient

$eventTypes = @('user.session.start', 'user.authentication.auth_via_mfa', 'user.session.access_admin_app', 'policy.evaluate_sign_on')
$logFilter = ($eventTypes | ForEach-Object { "eventType eq `"$_`"" }) -join ' or '

$byId = @{}
$byLogin = @{}
foreach ($login in ($Accounts -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $byLogin[$login.ToLowerInvariant()] = $login
    $user = Get-OktaUserByLogin -Client $client -Login $login
    if ($user) { $byId[[string]$user.id] = $login }
    else { Write-Warning "No Okta user found for $login; matching on login only." }
}
if ($byLogin.Count -eq 0) { throw '-Accounts must list at least one login.' }

function ConvertTo-BreakGlassRow {
    param($LogEvent)
    $actorId = [string]$LogEvent.actor.id
    $alt = ([string]$LogEvent.actor.alternateId).ToLowerInvariant()
    $account = if ($byId.ContainsKey($actorId)) { $byId[$actorId] } elseif ($byLogin.ContainsKey($alt)) { $byLogin[$alt] } else { $null }
    if (-not $account) { return }
    $geo = $LogEvent.client.geographicalContext
    $result = [string]$LogEvent.outcome.result
    if (-not $result) { $result = 'UNKNOWN' }
    [pscustomobject]@{
        Time     = ConvertTo-OktaIsoString $LogEvent.published
        Account  = $account
        Event    = [string]$LogEvent.eventType
        Result   = $result
        Reason   = [string]$LogEvent.outcome.reason
        IP       = [string]$LogEvent.client.ipAddress
        Location = (@($geo.city, $geo.country) | Where-Object { $_ }) -join ', '
    }
}

if (-not $Watch) {
    $since = [datetime]::UtcNow.AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $rows = @(Get-OktaLogs -Client $client -Filter $logFilter -Since $since | ForEach-Object { ConvertTo-BreakGlassRow $_ })
    if ($Json) {
        $text = ConvertTo-Json -InputObject $rows -Depth 5
        Write-Output $text
        if ($Output) { $text | Out-File -LiteralPath $Output -Encoding utf8 }
    } else {
        $rows | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
        Write-Output "$($rows.Count) events since $since"
        if ($Output) { $rows | Export-OktaCsv -Path $Output }
    }
    return
}

Write-Information "Watching $($byLogin.Count) account(s) every $Interval s. Ctrl+C to stop." -InformationAction Continue
$cursor = $null
$since = Get-OktaUtcNow
while ($true) {
    $poll = Get-OktaLogPoll -Client $client -Cursor $cursor -Filter $logFilter -Since $since
    $cursor = $poll.Cursor
    $new = @($poll.Events | ForEach-Object { ConvertTo-BreakGlassRow $_ })
    foreach ($row in $new) {
        if ($Json) { $row | ConvertTo-Json -Compress } else { "[{0}] {1} {2} {3} ip={4} {5}" -f $row.Time, $row.Account, $row.Event, $row.Result, $row.IP, $row.Location }
        if ($Output) {
            if ($Json) { $row | ConvertTo-Json -Compress | Out-File -LiteralPath $Output -Append -Encoding utf8 }
            else { $row | Export-OktaCsv -Path $Output -Append }
        }
    }
    Start-Sleep -Seconds $Interval
}
