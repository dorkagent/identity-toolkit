#Requires -Version 7.0
<#
.SYNOPSIS
    Finds dormant Okta accounts and can suspend or deactivate them.

.DESCRIPTION
    An ACTIVE user is flagged DORMANT when lastLogin is older than -Days, or
    NEVER_LOGGED_IN when there is no lastLogin and the account is older than
    -Days. lastLogin is the last Okta sign-in, not the last app use.

    Okta revokes a user's API tokens when the user is deactivated, so the
    script never touches:
      - the owner of the API token it is running with (GET /api/v1/users/me)
      - owners of any active API token (GET /api/v1/api-tokens; super admin only)
      - admin-role holders (GET /api/v1/iam/assignees/users)
      - logins or IDs in -ExcludeFile, and members of -ExcludeGroup

    Nothing changes without -Apply. -Action defaults to Suspend, which can be
    undone with Unsuspend; Deactivate is the harder option. -Limit caps how
    many accounts are changed. -Max refuses to start if more than that many
    would change.

.PARAMETER Days
    Idle threshold in days. Default 90.

.PARAMETER Action
    Suspend (default) or Deactivate.

.PARAMETER Apply
    Make the changes.

.PARAMETER Limit
    Change at most this many accounts. 0 means no cap.

.PARAMETER Max
    Refuse to apply if more than this many accounts would change. Default 25.

.PARAMETER ExcludeFile
    Text file of logins or user IDs to leave alone, one per line.

.PARAMETER ExcludeGroup
    Group names whose members are left alone.

.PARAMETER Json
    Print JSON instead of a table.

.PARAMETER Output
    Also write the report to this file (JSON with -Json, otherwise CSV).

.EXAMPLE
    ./Stale-AccountSweeper.ps1 -Days 90

    Report only.

.EXAMPLE
    ./Stale-AccountSweeper.ps1 -Days 180 -ExcludeGroup 'Service Accounts' -Apply -Limit 10

    Suspend up to 10 accounts idle for 180+ days, skipping the service account group.
#>
[CmdletBinding()]
param(
    [int]$Days = 90,
    [ValidateSet('Suspend', 'Deactivate')][string]$Action = 'Suspend',
    [switch]$Apply,
    [int]$Limit = 0,
    [int]$Max = 25,
    [string]$ExcludeFile,
    [string[]]$ExcludeGroup = @(),
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'
$client = New-OktaClient

$now = [datetime]::UtcNow
$cutoff = $now.AddDays(-$Days)

# Accounts that must never be swept: user id -> reason.
$protected = @{}
$me = Get-OktaCurrentUser -Client $client
if ($me) { $protected[[string]$me.id] = 'owns the API token this script is using' }
try {
    foreach ($t in Invoke-OktaPagedGet -Client $client -Path '/api/v1/api-tokens') {
        if ($t.userId -and -not $protected.ContainsKey([string]$t.userId)) { $protected[[string]$t.userId] = "owns API token '$($t.name)'" }
    }
} catch {
    if ($_.Exception.Data['StatusCode'] -ne 403) { throw }
    if ($me) {
        Write-Warning 'Cannot list API tokens (needs super admin); only the current token owner is protected.'
    } else {
        # OAuth service apps have no user behind them, so nothing is protected here.
        Write-Warning 'Cannot list API tokens (needs super admin and, for OAuth, okta.apiTokens.read); no API token owners are protected. List them in -ExcludeFile.'
    }
}
try {
    foreach ($uid in Get-OktaRoleAssigneeUserIds -Client $client) {
        if (-not $protected.ContainsKey($uid)) { $protected[$uid] = 'holds an admin role' }
    }
} catch {
    if ($_.Exception.Data['StatusCode'] -ne 403) { throw }
    Write-Warning 'Cannot list admin role holders; admins are not excluded automatically.'
}
foreach ($name in $ExcludeGroup) {
    $g = Get-OktaGroups -Client $client -Query $name | Where-Object { [string]$_.profile.name -eq $name } | Select-Object -First 1
    if (-not $g) { throw "Exclude group not found: $name" }
    foreach ($m in Invoke-OktaPagedGet -Client $client -Path "/api/v1/groups/$($g.id)/users") {
        if (-not $protected.ContainsKey([string]$m.id)) { $protected[[string]$m.id] = "member of excluded group '$name'" }
    }
}
$excluded = @{}
if ($ExcludeFile) {
    foreach ($line in Get-Content -LiteralPath $ExcludeFile) {
        $v = $line.Trim()
        if ($v -and -not $v.StartsWith('#')) { $excluded[$v.ToLowerInvariant()] = $true }
    }
}

# Find the stale accounts first; act on them afterwards.
$rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in Get-OktaUsers -Client $client -Status 'ACTIVE') {
    $last = ConvertTo-OktaUtcDate $u.lastLogin
    if ($last) {
        if ($last -ge $cutoff) { continue }
        $category = 'DORMANT'; $idle = [int]($now - $last).TotalDays
    } else {
        $created = ConvertTo-OktaUtcDate $u.created
        if (-not $created -or $created -ge $cutoff) { continue }
        $category = 'NEVER_LOGGED_IN'; $idle = [int]($now - $created).TotalDays
    }
    $skip = ''
    if ($protected.ContainsKey([string]$u.id)) { $skip = $protected[[string]$u.id] }
    elseif ($excluded.ContainsKey(([string]$u.profile.login).ToLowerInvariant()) -or $excluded.ContainsKey(([string]$u.id).ToLowerInvariant())) { $skip = 'listed in -ExcludeFile' }
    $rows.Add([pscustomobject]@{
        Login      = [string]$u.profile.login
        LastLogin  = if ($last) { $last.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'never' }
        DaysIdle   = $idle
        Category   = $category
        Action     = 'none'
        SkipReason = $skip
        UserId     = [string]$u.id
    })
}

$candidates = @($rows | Where-Object { -not $_.SkipReason })
$toChange = if ($Limit -gt 0) { [Math]::Min($Limit, $candidates.Count) } else { $candidates.Count }
if ($Apply -and $toChange -gt $Max) {
    throw "$toChange accounts would change, above -Max $Max. Narrow it with -Limit or raise -Max."
}

$verb = $Action.ToLowerInvariant()
$done = 0
foreach ($r in $rows) {
    if ($r.SkipReason) { $r.Action = 'skipped'; continue }
    if ($Limit -gt 0 -and $done -ge $Limit) { $r.Action = 'not processed (-Limit reached)'; continue }
    $done++
    if (-not $Apply) { $r.Action = "would $verb"; continue }
    try {
        $null = Invoke-OktaRequest -Client $client -Method POST -Path "/api/v1/users/$($r.UserId)/lifecycle/$verb"
        $r.Action = if ($verb -eq 'suspend') { 'suspended' } else { 'deactivated' }
    } catch {
        $r.Action = "failed: $($_.Exception.Message)"
    }
}

$report = @($rows | Select-Object Login, LastLogin, DaysIdle, Category, Action, SkipReason)
if ($Json) {
    $text = ConvertTo-Json -InputObject $report -Depth 5
    Write-Output $text
    if ($Output) { $text | Out-File -LiteralPath $Output -Encoding utf8 }
} else {
    $report | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
    $mode = if ($Apply) { 'APPLIED' } else { 'DRY RUN' }
    Write-Output "$($mode): $($rows.Count) stale, $($rows.Count - $candidates.Count) protected, $toChange $verb candidates"
    if ($Output) { $report | Export-OktaCsv -Path $Output }
}
