#Requires -Version 7.0
<#
.SYNOPSIS
    Joiner / mover / leaver changes for Okta, driven by a CSV file.

.DESCRIPTION
    CSV columns: login, firstName, lastName, email (optional, defaults to
    login), groups (names separated by ;), apps (app labels separated by ;).

      joiner  Create the user (staged, activate=false) or fix the profile of an
              existing one, then add the listed groups and apps.
      mover   Fix the profile and add missing groups and apps. With -Prune,
              also remove groups and apps that are not in the row.
      leaver  Deactivate the user and list what is still assigned.

    Nothing changes without -Apply. Re-running a file is safe; state that is
    already right is reported and left alone.

    Profile changes are sent with POST /api/v1/users/{id}, which only updates
    the fields sent. PUT would replace the whole profile and wipe every
    attribute that isn't in the CSV.

    -Prune only removes OKTA_GROUP memberships (never Everyone or groups
    imported from AD/LDAP) and only direct app assignments (not ones that
    come from a group). It skips a row whose groups or apps cell is empty, so
    a blank cell can't strip someone's access. Memberships added by a group
    rule come back on the next rule run; change the attribute instead.

    A failure on one row is recorded and the batch carries on. A 401 (bad
    credentials) stops the run.

.PARAMETER Mode
    joiner, mover or leaver.

.PARAMETER Csv
    Path to the input CSV.

.PARAMETER Apply
    Make the changes. Without it the script only reports.

.PARAMETER Prune
    Mover mode: remove groups and apps not listed in the row (see above).

.PARAMETER Json
    Print JSON instead of a table.

.PARAMETER Output
    Also write the report to this file (JSON with -Json, otherwise CSV).

.EXAMPLE
    ./JML-AutomationKit.ps1 -Mode joiner -Csv ./new-hires.csv

    Show what creating the new hires would change.

.EXAMPLE
    ./JML-AutomationKit.ps1 -Mode mover -Csv ./transfers.csv -Apply -Prune

    Update profiles, add missing access and remove access not in the file.

.EXAMPLE
    ./JML-AutomationKit.ps1 -Mode leaver -Csv ./exits.csv -Apply -Output ./leavers.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('joiner', 'mover', 'leaver')][string]$Mode,
    [Parameter(Mandatory)][string]$Csv,
    [switch]$Apply,
    [switch]$Prune,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Csv)) { throw "CSV file not found: $Csv" }
$client = New-OktaClient

$script:actions = [System.Collections.Generic.List[object]]::new()
$script:groupCache = @{}
$script:appCache = @{}

function Add-Action {
    param([string]$Login, [string]$Action, [string]$Detail, [string]$Status)
    $script:actions.Add([pscustomobject]@{ Login = $Login; Action = $Action; Status = $Status; Detail = $Detail })
}

function Invoke-Change {
    # Make a write when -Apply is set, otherwise record what would happen.
    param([string]$Login, [string]$Action, [string]$Detail, [string]$Method, [string]$Path, $Body)
    if (-not $Apply) { Add-Action $Login $Action "would $Detail" 'dry-run'; return $null }
    $result = Invoke-OktaRequest -Client $client -Method $Method -Path $Path -Body $Body
    Add-Action $Login $Action $Detail 'done'
    return $result
}

function Split-List {
    param([string]$Value)
    @(($Value -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Find-Group {
    param([string]$Name)
    if (-not $script:groupCache.ContainsKey($Name)) {
        $script:groupCache[$Name] = Get-OktaGroups -Client $client -Query $Name |
            Where-Object { [string]$_.profile.name -eq $Name } | Select-Object -First 1
    }
    return $script:groupCache[$Name]
}

function Find-App {
    param([string]$Label)
    if (-not $script:appCache.ContainsKey($Label)) {
        $script:appCache[$Label] = Invoke-OktaPagedGet -Client $client -Path '/api/v1/apps' -Query @{ q = $Label } |
            Where-Object { [string]$_.label -eq $Label } | Select-Object -First 1
    }
    return $script:appCache[$Label]
}

function Get-CurrentGroups {
    param([string]$UserId)
    $map = @{}
    foreach ($g in Invoke-OktaPagedGet -Client $client -Path "/api/v1/users/$UserId/groups") {
        if ($g.profile.name) { $map[[string]$g.profile.name] = $g }
    }
    return $map
}

function Get-CurrentApps {
    param([string]$UserId)
    $map = @{}
    $flt = "user.id eq `"$(ConvertTo-OktaFilterValue $UserId)`""
    foreach ($a in Invoke-OktaPagedGet -Client $client -Path '/api/v1/apps' -Query @{ filter = $flt }) {
        if ($a.label) { $map[[string]$a.label] = $a }
    }
    return $map
}

function Get-DesiredProfile {
    param($Row)
    $login = ([string]$Row.login).Trim()
    $email = ([string]$Row.email).Trim()
    if (-not $email) { $email = $login }
    return [ordered]@{
        firstName = ([string]$Row.firstName).Trim()
        lastName  = ([string]$Row.lastName).Trim()
        email     = $email
        login     = $login
    }
}

function Sync-Profile {
    param($User, $Row)
    $login = ([string]$Row.login).Trim()
    $changed = [ordered]@{}
    $want = Get-DesiredProfile $Row
    foreach ($k in $want.Keys) {
        if ([string]$User.profile.$k -cne $want[$k]) { $changed[$k] = $want[$k] }
    }
    if ($changed.Count -eq 0) { Add-Action $login 'update_profile' 'profile already matches' 'skipped'; return }
    $detail = 'update ' + (($changed.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')
    # POST = partial update; only the changed keys are sent.
    $null = Invoke-Change $login 'update_profile' $detail 'POST' "/api/v1/users/$($User.id)" @{ profile = $changed }
}

function Add-Groups {
    param([string]$Login, [string]$UserId, [string[]]$Names, [hashtable]$Have)
    foreach ($name in $Names) {
        if ($Have.ContainsKey($name)) { Add-Action $Login 'add_group' "already a member of $name" 'skipped'; continue }
        $g = Find-Group $name
        if (-not $g) { Add-Action $Login 'add_group' "group not found: $name" 'error'; continue }
        if ($g.type -ne 'OKTA_GROUP') {
            Add-Action $Login 'add_group' "$name is $($g.type); only OKTA_GROUP memberships can be changed" 'error'; continue
        }
        if (-not $UserId) { Add-Action $Login 'add_group' "would add to $name after creation" 'dry-run'; continue }
        $null = Invoke-Change $Login 'add_group' "add to $name" 'PUT' "/api/v1/groups/$($g.id)/users/$UserId" $null
    }
}

function Add-Apps {
    param([string]$Login, [string]$UserId, [string[]]$Labels, [hashtable]$Have)
    foreach ($label in $Labels) {
        if ($Have.ContainsKey($label)) { Add-Action $Login 'assign_app' "already assigned $label" 'skipped'; continue }
        $a = Find-App $label
        if (-not $a) { Add-Action $Login 'assign_app' "app not found: $label" 'error'; continue }
        if (-not $UserId) { Add-Action $Login 'assign_app' "would assign $label after creation" 'dry-run'; continue }
        $null = Invoke-Change $Login 'assign_app' "assign $label" 'POST' "/api/v1/apps/$($a.id)/users" @{ id = $UserId }
    }
}

function Remove-Extras {
    param([string]$Login, [string]$UserId, $Row, [hashtable]$HaveGroups, [hashtable]$HaveApps)
    $wantGroups = @(Split-List ([string]$Row.groups))
    $wantApps = @(Split-List ([string]$Row.apps))

    if ($wantGroups.Count -eq 0) {
        Add-Action $Login 'remove_group' 'groups cell is empty; not pruning groups' 'skipped'
    } else {
        foreach ($name in ($HaveGroups.Keys | Sort-Object)) {
            if ($wantGroups -contains $name) { continue }
            $g = $HaveGroups[$name]
            if ($g.type -ne 'OKTA_GROUP') {
                Add-Action $Login 'remove_group' "kept $($name): $($g.type) membership is not managed here" 'skipped'; continue
            }
            $null = Invoke-Change $Login 'remove_group' "remove from $name" 'DELETE' "/api/v1/groups/$($g.id)/users/$UserId" $null
        }
    }

    if ($wantApps.Count -eq 0) {
        Add-Action $Login 'unassign_app' 'apps cell is empty; not pruning apps' 'skipped'; return
    }
    foreach ($label in ($HaveApps.Keys | Sort-Object)) {
        if ($wantApps -contains $label) { continue }
        $aid = $HaveApps[$label].id
        $appUser = Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/apps/$aid/users/$UserId"
        if ($appUser.scope -ne 'USER') {
            Add-Action $Login 'unassign_app' "kept $($label): assigned through a group (scope $($appUser.scope))" 'skipped'; continue
        }
        $null = Invoke-Change $Login 'unassign_app' "unassign $label" 'DELETE' "/api/v1/apps/$aid/users/$UserId" $null
    }
}

$rows = @(Import-Csv -LiteralPath $Csv)
if (-not $Apply) { Write-Warning 'Dry run: nothing will change. Add -Apply to make the changes.' }

foreach ($r in $rows) {
    $login = ([string]$r.login).Trim()
    if (-not $login) { Add-Action '?' $Mode 'row has no login' 'error'; continue }
    try {
        $user = Get-OktaUserByLogin -Client $client -Login $login
        $groups = @(Split-List ([string]$r.groups))
        $apps = @(Split-List ([string]$r.apps))
        switch ($Mode) {
            'joiner' {
                if (-not $user) {
                    $created = Invoke-Change $login 'create_user' 'create user (staged, activate=false)' 'POST' `
                        '/api/v1/users?activate=false' @{ profile = (Get-DesiredProfile $r) }
                    $uid = if ($created) { [string]$created.id } else { $null }
                    Add-Groups $login $uid $groups @{}
                    Add-Apps $login $uid $apps @{}
                } else {
                    Sync-Profile $user $r
                    Add-Groups $login $user.id $groups (Get-CurrentGroups $user.id)
                    Add-Apps $login $user.id $apps (Get-CurrentApps $user.id)
                }
            }
            'mover' {
                if (-not $user) { Add-Action $login 'update_profile' 'user not found' 'error'; break }
                Sync-Profile $user $r
                $haveGroups = Get-CurrentGroups $user.id
                $haveApps = Get-CurrentApps $user.id
                Add-Groups $login $user.id $groups $haveGroups
                Add-Apps $login $user.id $apps $haveApps
                if ($Prune) {
                    Remove-Extras $login $user.id $r $haveGroups $haveApps
                } else {
                    $extra = @($haveGroups.Keys | Where-Object { $groups -notcontains $_ }) +
                             @($haveApps.Keys | Where-Object { $apps -notcontains $_ })
                    if ($extra.Count) { Add-Action $login 'extras' ("not in CSV, kept (no -Prune): " + ($extra -join ', ')) 'info' }
                }
            }
            'leaver' {
                if (-not $user) { Add-Action $login 'deactivate' 'user not found' 'error'; break }
                if ($user.status -eq 'DEPROVISIONED') {
                    Add-Action $login 'deactivate' 'already deactivated' 'skipped'
                } else {
                    $null = Invoke-Change $login 'deactivate' 'deactivate user' 'POST' "/api/v1/users/$($user.id)/lifecycle/deactivate" $null
                }
                $remainingApps = (Get-CurrentApps $user.id).Keys | Sort-Object
                $remainingGroups = (Get-CurrentGroups $user.id).Keys | Sort-Object
                Add-Action $login 'remaining_apps' ((@($remainingApps) -join ', ') -replace '^$', 'none') 'info'
                Add-Action $login 'remaining_groups' ((@($remainingGroups) -join ', ') -replace '^$', 'none') 'info'
            }
        }
    } catch {
        if ($_.Exception.Data['StatusCode'] -eq 401) { throw }
        Add-Action $login $Mode $_.Exception.Message 'error'
    }
}

$report = @($script:actions)
if ($Json) {
    $text = ConvertTo-Json -InputObject $report -Depth 6
    Write-Output $text
    if ($Output) { $text | Out-File -LiteralPath $Output -Encoding utf8 }
} else {
    $report | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Output
    if ($Output) { $report | Export-OktaCsv -Path $Output }
}
