#Requires -Version 7.0
<#
.SYNOPSIS
    Maps every privilege path to Okta admin roles: direct, via group, via group rule.

.DESCRIPTION
    Shows HOW each user holds admin rights, not just that they do. Three
    path types are reported:

      Direct   - the role is assigned straight to the user
                 (GET /api/v1/users/{id}/roles, entries with
                 assignmentType USER; GROUP entries there are inherited and
                 come from the group pass instead). Via shows '(direct grant)'.
      ViaGroup - the user inherits the role through group membership. Via
                 names the group (GET /api/v1/groups/{id}/roles plus
                 GET /api/v1/groups/{id}/users).
      ViaRule  - a group rule feeds users into a group that holds admin
                 roles, so the rule itself is an escalation vector. Via
                 shows 'rule name -> group name' (GET /api/v1/groups/rules,
                 actions.assignUserToGroups.groupIds).

    Dormant: users whose lastLogin is older than -DormantDays, or who never
    logged in, get Dormant = 'yes'. A per-user rollup follows the path table
    and counts how many separate paths each account has.

    Read-only: every call is a GET.

    Custom roles show as CUSTOM:<label>. Their resource sets are not
    resolved yet, so a CUSTOM row says the user holds that role but not what
    it can touch.

    Performance: direct grants cost one /roles call per user, so big tenants
    are slow. Use -Limit for a trial run over N users first.

    Scope notes: only ACTIVE users are enumerated (suspended or deprovisioned
    accounts hold no effective access); only ACTIVE group rules can feed
    groups. Okta does not record whether a group member arrived via a rule
    or a manual add, so ViaRule rows cover the current members of rule-fed
    admin groups - the rule is the path to audit.

.PARAMETER DormantDays
    Users whose lastLogin is older than this many days, or who never logged
    in, are flagged dormant. Default 90.

.PARAMETER Limit
    Maximum number of users to enumerate. 0 (default) = all users. Trial
    runs: -Limit 25 checks the first 25 users.

.PARAMETER Json
    Emit the report (paths + per-user rollup + feeding rules) as JSON
    instead of console tables.

.PARAMETER Output
    Write the report to a file. CSV of the path rows by default, JSON
    (paths + rollup) with -Json.

.EXAMPLE
    pwsh ./Get-PrivilegePath.ps1
    Privilege-path map for every ACTIVE user, dormant and highest roles first.

.EXAMPLE
    pwsh ./Get-PrivilegePath.ps1 -DormantDays 30 -Limit 25
    Trial run over 25 users with a 30-day dormancy threshold.

.EXAMPLE
    pwsh ./Get-PrivilegePath.ps1 -Json -Output privilege-paths.json
    Writes the JSON report (paths + rollup + feeding rules) to a file.
#>

param(
    [int]$DormantDays = 90,
    [int]$Limit = 0,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

$ErrorActionPreference = 'Stop'

function Get-RoleRank {
    param([string]$Type)
    switch ($Type) {
        'SUPER_ADMIN'                 { return 1 }
        'ORG_ADMIN'                   { return 2 }
        'APP_ADMIN'                   { return 3 }
        'USER_ADMIN'                  { return 4 }
        'HELP_DESK_ADMIN'             { return 5 }
        'GROUP_MEMBERSHIP_ADMIN'      { return 6 }
        'API_ACCESS_MANAGEMENT_ADMIN' { return 7 }
        'WORKFLOWS_ADMIN'             { return 8 }
        'ACCESS_REQUESTS_ADMIN'       { return 9 }
        'ACCESS_CERTIFICATIONS_ADMIN' { return 10 }
        'READ_ONLY_ADMIN'             { return 11 }
        'REPORT_ADMIN'                { return 12 }
        default {
            # Custom roles can carry anything; rank them with the high ones until resource sets are resolved.
            if ($Type -like 'CUSTOM*') { return 3 }
            return 50
        }
    }
}

function Get-UserLabel {
    param($User)
    $login = [string]$User.profile.login
    if (-not $login) { $login = [string]$User.id }
    $name = (@($User.profile.firstName, $User.profile.lastName) -join ' ').Trim()
    return [pscustomobject]@{ Login = $login; Name = $name }
}

function Get-DormantState {
    param($User, [datetime]$Cutoff)
    $lastLoginRaw = $User.lastLogin
    $neverLoggedIn = ($null -eq $lastLoginRaw) -or ('' -eq "$lastLoginRaw")
    if ($neverLoggedIn) { return 'NEVER_LOGGED_IN' }
    if ((ConvertTo-OktaUtcDate $lastLoginRaw) -lt $Cutoff) { return 'DORMANT' }
    return 'ACTIVE'
}

function Register-UserInfo {
    param($User)
    $uid = [string]$User.id
    if (-not $infoById.ContainsKey($uid)) {
        $label = Get-UserLabel -User $User
        $state = Get-DormantState -User $User -Cutoff $cutoff
        $infoById[$uid] = [pscustomobject]@{
            Login   = $label.Login
            Name    = $label.Name
            Dormant = if ($state -eq 'ACTIVE') { 'no' } else { 'yes' }
            Flag    = if ($state -eq 'ACTIVE') { '' } else { $state }
        }
    }
    return $infoById[$uid]
}

function New-PathRow {
    param(
        [string]$UserId,
        [string]$PathType,
        [string]$Via,
        $Role
    )
    $info = $infoById[$UserId]
    if (-not $info) { return $null }
    $roleType = 'UNKNOWN'
    if ($Role -and $Role.type) { $roleType = [string]$Role.type }
    if ($roleType -eq 'CUSTOM') { $roleType = "CUSTOM:$($Role.label)" }
    $flags = @()
    switch ($PathType) {
        'Direct'   { $flags += 'DIRECT_GRANT' }
        'ViaGroup' { $flags += 'INHERITED' }
        'ViaRule'  { $flags += 'RULE_FED' }
    }
    if ($info.Flag) { $flags += $info.Flag }
    return [pscustomobject]@{
        User     = $info.Login
        Name     = $info.Name
        PathType = $PathType
        Via      = $Via
        Role     = $roleType
        Dormant  = $info.Dormant
        Flags    = ($flags -join '; ')
    }
}

$now = (Get-Date).ToUniversalTime()
$cutoff = $now.AddDays(-$DormantDays)
$pathRank = @{ Direct = 0; ViaGroup = 1; ViaRule = 2 }
$infoById = @{}
$warnings = @()
$rows = @()

$users = @(Get-OktaUsers -Client $client -Status 'ACTIVE')
if ($Limit -gt 0) { $users = @($users | Select-Object -First $Limit) }
foreach ($u in $users) { Register-UserInfo -User $u | Out-Null }

# (1) Direct grants: one /roles call per user.
foreach ($u in $users) {
    $uid = [string]$u.id
    try {
        $directRoles = @(Get-OktaUserRoles -Client $client -UserId $uid)
    } catch {
        $warnings += "direct roles for user $uid skipped: $($_.Exception.Message)"
        continue
    }
    foreach ($r in @($directRoles | Where-Object { $_.assignmentType -ne 'GROUP' })) {
        $row = New-PathRow -UserId $uid -PathType 'Direct' -Via '(direct grant)' -Role $r
        if ($row) { $rows += $row }
    }
}

# (2) Group grants: members of any group holding role assignments inherit them.
$privilegedGroups = @{}
$membersByGroup = @{}
$skippedNonActive = 0
$groups = @(Get-OktaGroups -Client $client)
foreach ($g in $groups) {
    $gid = [string]$g.id
    try {
        $groupRoles = @(Get-OktaGroupRoles -Client $client -GroupId $gid)
    } catch {
        $warnings += "group roles for group $gid skipped: $($_.Exception.Message)"
        continue
    }
    if ($groupRoles.Count -eq 0) { continue }
    $gname = $gid
    if ($g.profile.name) { $gname = [string]$g.profile.name }
    $privilegedGroups[$gid] = [pscustomobject]@{ Name = $gname; Roles = @($groupRoles) }
    try {
        $members = @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/groups/$gid/users")
    } catch {
        $warnings += "members of group '$gname' skipped: $($_.Exception.Message)"
        continue
    }
    $membersByGroup[$gid] = $members
    foreach ($m in $members) {
        $mid = [string]$m.id
        # Only ACTIVE users hold effective access. Suspended/deprovisioned
        # members of an admin-granting group are not live privilege paths;
        # they are counted and excluded so the report does not overstate.
        if ([string]$m.status -ne 'ACTIVE') { $skippedNonActive++; continue }
        Register-UserInfo -User $m | Out-Null
        foreach ($r in $groupRoles) {
            $row = New-PathRow -UserId $mid -PathType 'ViaGroup' -Via $gname -Role $r
            if ($row) { $rows += $row }
        }
    }
}

# (3) Group rules feeding admin-granting groups: the rule is the escalation vector.
$ruleFedNames = @()
try {
    $rules = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/groups/rules')
} catch {
    $warnings += "group rules skipped: $($_.Exception.Message)"
    $rules = @()
}
foreach ($rule in $rules) {
    if ([string]$rule.status -ne 'ACTIVE') { continue }
    $assign = $rule.actions.assignUserToGroups
    if (-not $assign -or -not $assign.groupIds) { continue }
    $ruleName = [string]$rule.id
    if ($rule.name) { $ruleName = [string]$rule.name }
    foreach ($targetId in @($assign.groupIds)) {
        $tid = [string]$targetId
        if (-not $privilegedGroups.ContainsKey($tid)) { continue }
        if ($ruleFedNames -notcontains $ruleName) { $ruleFedNames += $ruleName }
        $pg = $privilegedGroups[$tid]
        foreach ($m in $membersByGroup[$tid]) {
            $mid = [string]$m.id
            foreach ($r in $pg.Roles) {
                $viaText = "$ruleName -> $($pg.Name)"
                $row = New-PathRow -UserId $mid -PathType 'ViaRule' -Via $viaText -Role $r
                if ($row) { $rows += $row }
            }
        }
    }
}

# Sort: dormant first, then role rank, then path type, then user.
$byScary = @(
    @{ Expression = { if ($_.Dormant -eq 'yes') { 0 } else { 1 } } }
    @{ Expression = { Get-RoleRank -Type ([string]$_.Role) } }
    @{ Expression = { $pathRank[[string]$_.PathType] } }
    @{ Expression = { [string]$_.User } }
    @{ Expression = { [string]$_.Role } }
)
$rows = @($rows | Sort-Object -Property $byScary)

# Per-user rollup: how many separate paths each account has.
$byRollup = @(
    @{ Expression = { if ($_.Dormant -eq 'yes') { 0 } else { 1 } } }
    @{ Expression = { $_.Paths }; Descending = $true }
    @{ Expression = { [string]$_.User } }
)
$rollup = @(
    $rows | Group-Object -Property User | ForEach-Object {
        $grows = $_.Group
        $first = $grows | Select-Object -First 1
        [pscustomobject]@{
            User     = $_.Name
            Name     = $first.Name
            Paths    = $grows.Count
            Direct   = @($grows | Where-Object { $_.PathType -eq 'Direct' }).Count
            ViaGroup = @($grows | Where-Object { $_.PathType -eq 'ViaGroup' }).Count
            ViaRule  = @($grows | Where-Object { $_.PathType -eq 'ViaRule' }).Count
            Roles    = (@($grows | Select-Object -ExpandProperty Role -Unique) -join '; ')
            Dormant  = $first.Dormant
        }
    } | Sort-Object -Property $byRollup
)

$privilegedUserCount = @($rows | Select-Object -ExpandProperty User -Unique).Count
$dormantUserCount = @($rollup | Where-Object { $_.Dormant -eq 'yes' }).Count
$viaRuleCount = @($rows | Where-Object { $_.PathType -eq 'ViaRule' }).Count
if ($skippedNonActive -gt 0) {
    $warnings += "$skippedNonActive non-ACTIVE member(s) of admin-granting groups were excluded (suspended/deprovisioned accounts hold no effective access)"
}
$summary = "Privilege paths: $($rows.Count) across $privilegedUserCount privileged users " +
    "($dormantUserCount dormant); $($ruleFedNames.Count) group rule(s) feed admin-granting " +
    "groups ($viaRuleCount rule-fed paths)."

if ($Json) {
    $report = [pscustomobject]@{
        GeneratedUtc            = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        DormantDays             = $DormantDays
        Summary                 = $summary
        RulesFeedingAdminGroups = @($ruleFedNames)
        PrivilegePaths          = @($rows)
        UserRollup              = @($rollup)
    }
    $payload = $report | ConvertTo-Json -Depth 10
    if ($payload) { Write-Output $payload }
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} else {
    Write-Output $summary
    Write-Output ''
    if ($rows.Count -eq 0) {
        Write-Output 'No admin role assignments found in scope.'
    } else {
        $rows | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Output
        Write-Output 'Per-user rollup (accounts with several paths are worth reviewing first):'
        $rollup | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
    }
    if ($Output) {
        if ($rows.Count -gt 0) {
            $rows | Export-OktaCsv -Path $Output
        } else {
            Write-Output 'No privilege paths found; no CSV written.'
        }
    }
}

if ($warnings.Count -gt 0) {
    Write-Output ''
    Write-Output 'Warnings (objects skipped, results may be incomplete):'
    $warnings | ForEach-Object { Write-Output "  $_" }
}
