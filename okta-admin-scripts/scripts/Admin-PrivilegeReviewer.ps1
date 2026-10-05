<#
.SYNOPSIS
    Reviews Okta admin privilege assignments for stale grants and MFA coverage. (DHQ-85, read-only)

.DESCRIPTION
    For every ACTIVE user, collects direct admin role assignments via
    Get-OktaUserRoles and group-held admin roles via Get-OktaGroupRoles, for
    the elevated role types: SUPER_ADMIN, ORG_ADMIN, APP_ADMIN, GROUP_ADMIN,
    GROUP_MEMBERSHIP_ADMIN, HELP_DESK_ADMIN, MOBILE_ADMIN,
    API_ACCESS_MANAGEMENT_ADMIN, USER_ADMIN.

    Each holder is checked for:
      - Grant date (role assignmentDate, falling back to created).
      - Last System Log activity as actor (or "none").
      - MFA enrollment: active factor count plus whether any webauthn/smart_card factor is enrolled.
      - STALE: grant date older than -StaleDays AND no System Log activity in that window.

    Authentication comes from the OKTA_DOMAIN / OKTA_API_TOKEN environment
    variables only.

.PARAMETER StaleDays
    A grant is STALE when its grant date is older than this many days AND the
    holder has no System Log activity in the same window. Default 180.

.PARAMETER Json
    Emit the report as JSON instead of a table.

.PARAMETER Output
    Write the report to this file path (JSON with -Json, CSV otherwise).

.EXAMPLE
    .\Admin-PrivilegeReviewer.ps1

    Review all admin privilege holders with the default 180-day staleness window.

.EXAMPLE
    .\Admin-PrivilegeReviewer.ps1 -StaleDays 90 -Json -Output .\privilege-review.json

    Review with a 90-day staleness window and write a JSON report to file.

.EXAMPLE
    .\Admin-PrivilegeReviewer.ps1 -Output .\privilege-review.csv

    Review and save a CSV report while still printing the table to the console.
#>

param(
    [int]$StaleDays = 180,
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

$ElevatedRoles = @(
    'SUPER_ADMIN',
    'ORG_ADMIN',
    'APP_ADMIN',
    'GROUP_ADMIN',
    'GROUP_MEMBERSHIP_ADMIN',
    'HELP_DESK_ADMIN',
    'MOBILE_ADMIN',
    'API_ACCESS_MANAGEMENT_ADMIN',
    'USER_ADMIN'
)

# userId -> @{ Roles = @(); GrantDates = @() }
$holders = @{}

function Get-RoleGrantDate {
    param($Role)
    if ($Role.assignmentDate) { return [string]$Role.assignmentDate }
    if ($Role.created) { return [string]$Role.created }
    return ""
}

function Add-HolderRole {
    param([string]$UserId, [string]$RoleLabel, [string]$GrantDate)
    if (-not $script:holders.ContainsKey($UserId)) {
        $script:holders[$UserId] = @{ Roles = @(); GrantDates = @() }
    }
    if ($script:holders[$UserId].Roles -notcontains $RoleLabel) {
        $script:holders[$UserId].Roles += $RoleLabel
    }
    if ($GrantDate) { $script:holders[$UserId].GrantDates += $GrantDate }
}

$script:holders = $holders

# Direct role assignments on every ACTIVE user.
$users = @(Get-OktaUsers -Client $client)
$userById = @{}
foreach ($u in $users) { $userById[[string]$u.id] = $u }
foreach ($u in $users) {
    $roles = @(Get-OktaUserRoles -Client $client -UserId $u.id)
    foreach ($r in $roles) {
        if ($ElevatedRoles -contains $r.type) {
            Add-HolderRole -UserId ([string]$u.id) -RoleLabel ([string]$r.type) -GrantDate (Get-RoleGrantDate -Role $r)
        }
    }
}

# Group-held roles: record group name + role type against each active member.
$groups = @(Get-OktaGroups -Client $client)
foreach ($g in $groups) {
    $groles = @(Get-OktaGroupRoles -Client $client -GroupId $g.id)
    $elevated = @($groles | Where-Object { $ElevatedRoles -contains $_.type })
    if ($elevated.Count -eq 0) { continue }
    $members = @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/groups/$($g.id)/users")
    foreach ($m in $members) {
        if ([string]$m.status -ne 'ACTIVE') { continue }
        $mid = [string]$m.id
        if (-not $userById.ContainsKey($mid)) { $userById[$mid] = $m }
        foreach ($r in $elevated) {
            $label = "$($r.type) (group: $($g.name))"
            Add-HolderRole -UserId $mid -RoleLabel $label -GrantDate (Get-RoleGrantDate -Role $r)
        }
    }
}

$cutoff = Get-UtcIso8601 -When ((Get-Date).AddDays(-$StaleDays))
$staleThreshold = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)

$rows = @()
foreach ($uid in $script:holders.Keys) {
    $u = $userById[$uid]
    $login = [string]$u.profile.login
    $name = ("{0} {1}" -f [string]$u.profile.firstName, [string]$u.profile.lastName).Trim()

    $grantDates = @($script:holders[$uid].GrantDates | Where-Object { $_ } | Sort-Object)
    $grantDate = ""
    if ($grantDates.Count -gt 0) { $grantDate = $grantDates[0] }

    $logFilter = "actor.id eq `"$uid`""
    $events = @(Get-OktaLogs -Client $client -Filter $logFilter -Since $cutoff)
    $lastAction = "none"
    if ($events.Count -gt 0) { $lastAction = [string]$events[$events.Count - 1].published }

    $factors = @(Get-OktaFactors -Client $client -UserId $uid)
    $activeFactors = @($factors | Where-Object { $_.status -eq 'ACTIVE' })
    $strong = @($activeFactors | Where-Object { $_.factorType -eq 'webauthn' -or $_.factorType -eq 'smart_card' })
    $mfa = "$($activeFactors.Count)"
    if ($strong.Count -gt 0) { $mfa = "$($activeFactors.Count) (webauthn/smart_card)" }

    $stale = "no"
    if ($grantDate) {
        $parsed = $grantDate -as [datetime]
        if ($parsed -and $parsed.ToUniversalTime() -lt $staleThreshold -and $events.Count -eq 0) {
            $stale = "STALE"
        }
    }

    $rows += [pscustomobject]@{
        Login           = $login
        Name            = $name
        Roles           = ($script:holders[$uid].Roles -join '; ')
        GrantDate       = $grantDate
        LastAdminAction = $lastAction
        MFA             = $mfa
        Stale           = $stale
    }
}

$rows = @($rows | Sort-Object Login)

if ($Json) {
    $report = ($rows | ConvertTo-Json -Depth 10)
    Write-Output $report
    if ($Output) { $report | Out-File -FilePath $Output -Encoding utf8 }
} else {
    $rows | Format-Table -AutoSize
    if ($Output) { $rows | Export-Csv -Path $Output -NoTypeInformation }
}
