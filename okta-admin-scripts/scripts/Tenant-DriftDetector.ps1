#Requires -Version 7.0
<#
.SYNOPSIS
    Captures, lists, and diffs read-only tenant configuration snapshots for drift detection.

.DESCRIPTION
    Read-only. Three modes:

    -Snapshot : capture tenant configuration to a snapshot file under
                -SnapshotDir (default ./snapshots), named
                <domain-slug>-<YYYYMMDD-HHMMSS>.json. The snapshot contains
                meta {domain, timestamp} and data {policies, zones,
                authServers, apps, adminRoles}, where:
                  policies   = id, name, type, plus rules (id, name, actions, conditions)
                  zones      = full zone objects
                  authServers= full authorization server objects
                  apps       = id, label, name, signOnMode, assignedUserIds
                  adminRoles = userId, login, roleType, label, assignmentType, grantDate
                The snapshots directory is created if missing.

    -Diff <OldPath>,<NewPath> : compare two snapshots grouped by resource type,
                reporting added / removed / changed entries. Entries are keyed
                by id; adminRoles entries are keyed by (userId, roleType, label, assignmentType).
                Volatile fields (created, lastUpdated, _links, lastLogin,
                statusChanged, passwordChanged) are ignored recursively.
                Human-readable grouped +/-/~ output by default; -Json for
                automation.

    -List     : list snapshot files in -SnapshotDir with timestamps (default
                mode when no mode flag is given).

    Table output by default; -Json for machine-readable output; -Output writes
    the report to a file. Only -Snapshot needs Okta credentials.

    The snapshot format differs from tenant_drift_detector.py's, so diff
    snapshots made by the same script.

.PARAMETER Snapshot
    Capture a new tenant snapshot.

.PARAMETER Diff
    Two snapshot file paths to compare: -Diff <OldPath>,<NewPath> (comma between the two paths).

.PARAMETER List
    List snapshot files in -SnapshotDir.

.PARAMETER SnapshotDir
    Directory holding snapshot files. Default "./snapshots".

.PARAMETER Json
    Emit the report as JSON instead of human-readable text/table.

.PARAMETER Output
    Write the report to this file path as well as displaying it.

.EXAMPLE
    .\Tenant-DriftDetector.ps1 -Snapshot
    Capture the current tenant configuration to snapshots/.

.EXAMPLE
    .\Tenant-DriftDetector.ps1 -Diff .\snapshots\dev-123456-20260901-000000.json,.\snapshots\dev-123456-20260928-000000.json
    Show what changed between two snapshots.

.EXAMPLE
    .\Tenant-DriftDetector.ps1 -List
    List captured snapshots with timestamps.
#>

[CmdletBinding(DefaultParameterSetName = "List")]
param(
    [Parameter(ParameterSetName = "Snapshot")][switch]$Snapshot,
    [Parameter(ParameterSetName = "Diff")][ValidateCount(2, 2)][string[]]$Diff,
    [Parameter(ParameterSetName = "List")][switch]$List,
    [string]$SnapshotDir = "./snapshots",
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'

$script:VolatileFields = @('created', 'lastUpdated', '_links', 'lastLogin', 'statusChanged', 'passwordChanged')

function ConvertTo-PlainObject {
    # Recursively rebuild a PSCustomObject/hashtable/array into ordered
    # hashtables with sorted keys, dropping volatile fields. This gives a
    # canonical shape for drift comparison.
    param($Obj)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in (@($Obj.Keys) | Sort-Object)) {
            if ($script:VolatileFields -contains $k) { continue }
            $h[$k] = ConvertTo-PlainObject $Obj[$k]
        }
        return $h
    }
    if ($Obj -is [pscustomobject]) {
        $h = [ordered]@{}
        foreach ($name in (@($Obj.PSObject.Properties.Name) | Sort-Object)) {
            if ($script:VolatileFields -contains $name) { continue }
            $h[$name] = ConvertTo-PlainObject $Obj.$name
        }
        return $h
    }
    if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
        $a = New-Object System.Collections.ArrayList
        foreach ($x in $Obj) { [void]$a.Add((ConvertTo-PlainObject $x)) }
        return @($a)
    }
    return $Obj
}

function Get-ChangedPaths {
    # Recursively collect dot/bracket paths that differ between two
    # normalized values.
    param($Old, $New, [string]$Path)
    $diffs = New-Object System.Collections.ArrayList
    if ($null -eq $Old -and $null -eq $New) { return @($diffs) }
    if ($null -eq $Old -or $null -eq $New) {
        [void]$diffs.Add($Path)
        return @($diffs)
    }
    $oldIsMap = ($Old -is [System.Collections.IDictionary])
    $newIsMap = ($New -is [System.Collections.IDictionary])
    if ($oldIsMap -and $newIsMap) {
        $keys = @((@($Old.Keys) + @($New.Keys)) | Select-Object -Unique | Sort-Object)
        foreach ($k in $keys) {
            $p = $k
            if ($Path) { $p = "$Path.$k" }
            $ov = $null
            if ($Old.Contains($k)) { $ov = $Old[$k] }
            $nv = $null
            if ($New.Contains($k)) { $nv = $New[$k] }
            foreach ($d in (Get-ChangedPaths -Old $ov -New $nv -Path $p)) { [void]$diffs.Add($d) }
        }
        return @($diffs)
    }
    $oldIsArr = ($Old -is [System.Collections.IEnumerable] -and $Old -isnot [string])
    $newIsArr = ($New -is [System.Collections.IEnumerable] -and $New -isnot [string])
    if ($oldIsArr -and $newIsArr) {
        $oa = @($Old)
        $na = @($New)
        if ($oa.Count -ne $na.Count) {
            [void]$diffs.Add("$Path (count $($oa.Count) -> $($na.Count))")
        }
        $n = [Math]::Min($oa.Count, $na.Count)
        for ($i = 0; $i -lt $n; $i++) {
            foreach ($d in (Get-ChangedPaths -Old $oa[$i] -New $na[$i] -Path "$Path[$i]")) { [void]$diffs.Add($d) }
        }
        return @($diffs)
    }
    if ("$Old" -ne "$New") { [void]$diffs.Add($Path) }
    return @($diffs)
}

function Get-ResourceKey {
    param([string]$Type, $Item)
    if ($Type -eq "adminRoles") { return "$($Item.userId)|$($Item.roleType)|$($Item.label)|$($Item.assignmentType)" }
    return [string]$Item.id
}

function Get-ResourceLabel {
    param([string]$Type, $Item)
    if ($Type -eq "adminRoles") { return "$($Item.login) : $($Item.roleType) $($Item.label) ($($Item.assignmentType))" }
    if ($Type -eq "apps") { return [string]$Item.label }
    return [string]$Item.name
}

function Write-ReportText {
    param([string]$Text)
    if ($Output) { $Text | Out-File -FilePath $Output -Encoding utf8 }
    Write-Output $Text
}

# =============================================================================
# -Snapshot mode
# =============================================================================
if ($Snapshot) {
    $client = New-OktaClient   # only snapshot mode talks to Okta
    if (-not (Test-Path $SnapshotDir)) {
        New-Item -ItemType Directory -Path $SnapshotDir -Force | Out-Null
    }

    $domainHost = ([uri]$client.BaseUrl).Host
    $slug = $domainHost -replace "\.okta\.com$", "" -replace "\.oktapreview\.com$", "" -replace "\.okta-emea\.com$", ""
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $file = Join-Path $SnapshotDir "$slug-$stamp.json"

    $policies = New-Object System.Collections.ArrayList
    # Values from the PolicyType enum. ACCESS_POLICY and POST_AUTH_SESSION
    # exist only on Identity Engine; Classic orgs reject them, so a failure
    # on one type is reported and skipped.
    $policyTypes = @('OKTA_SIGN_ON', 'ACCESS_POLICY', 'PASSWORD', 'MFA_ENROLL', 'IDP_DISCOVERY', 'POST_AUTH_SESSION')
    foreach ($t in $policyTypes) {
        try { $found = @(Get-OktaPolicies -Client $client -Type $t) }
        catch { Write-Warning "Skipped policy type $($t): $($_.Exception.Message)"; continue }
        foreach ($p in $found) {
            $rules = New-Object System.Collections.ArrayList
            foreach ($r in @(Get-OktaPolicyRules -Client $client -PolicyId ([string]$p.id))) {
                [void]$rules.Add([pscustomobject]@{
                    id         = [string]$r.id
                    name       = [string]$r.name
                    actions    = $r.actions
                    conditions = $r.conditions
                })
            }
            [void]$policies.Add([pscustomobject]@{
                id    = [string]$p.id
                name  = [string]$p.name
                type  = [string]$p.type
                rules = @($rules)
            })
        }
    }

    $zones = New-Object System.Collections.ArrayList
    foreach ($z in @(Get-OktaZones -Client $client)) { [void]$zones.Add($z) }

    $authServers = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-OktaAuthServers -Client $client)) { [void]$authServers.Add($a) }

    $apps = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-OktaApps -Client $client)) {
        $userIds = New-Object System.Collections.ArrayList
        foreach ($u in @(Get-OktaAppUsers -Client $client -AppId ([string]$a.id))) {
            [void]$userIds.Add([string]$u.id)
        }
        [void]$apps.Add([pscustomobject]@{
            id              = [string]$a.id
            label           = [string]$a.label
            name            = [string]$a.name
            signOnMode      = [string]$a.signOnMode
            assignedUserIds = @($userIds)
        })
    }

    $adminRoles = New-Object System.Collections.ArrayList
    foreach ($uid in Get-OktaRoleAssigneeUserIds -Client $client) {
        $u = Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/users/$uid"
        foreach ($r in @(Get-OktaUserRoles -Client $client -UserId $uid)) {
            [void]$adminRoles.Add([pscustomobject]@{
                userId         = $uid
                login          = [string]$u.profile.login
                roleType       = [string]$r.type
                label          = [string]$r.label
                assignmentType = [string]$r.assignmentType
                grantDate      = ConvertTo-OktaIsoString $r.created
            })
        }
    }

    $snapshotDoc = [pscustomobject]@{
        meta = [pscustomobject]@{
            domain    = $client.BaseUrl
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        data = [pscustomobject]@{
            policies    = @($policies)
            zones       = @($zones)
            authServers = @($authServers)
            apps        = @($apps)
            adminRoles  = @($adminRoles)
        }
    }

    $snapshotDoc | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $file -Encoding utf8
    if (-not $IsWindows) { chmod 600 $file }   # the snapshot holds your whole policy setup
    Write-Output "Snapshot written to $file"
    exit 0
}

# =============================================================================
# -Diff mode
# =============================================================================
if ($Diff) {
    if ($Diff.Count -ne 2) { throw "Use -Diff <OldSnapshot> <NewSnapshot> with exactly two snapshot paths." }
    if (-not (Test-Path $Diff[0])) { throw "Old snapshot not found: $($Diff[0])" }
    if (-not (Test-Path $Diff[1])) { throw "New snapshot not found: $($Diff[1])" }

    $oldSnap = Get-Content -Raw -Path $Diff[0] | ConvertFrom-Json
    $newSnap = Get-Content -Raw -Path $Diff[1] | ConvertFrom-Json

    $types = @("policies", "zones", "authServers", "apps", "adminRoles")
    $diffResult = [ordered]@{}
    foreach ($t in $types) {
        $oldArr = $oldSnap.data.$t
        if ($null -eq $oldArr) { $oldArr = @() } else { $oldArr = @($oldArr) }
        $newArr = $newSnap.data.$t
        if ($null -eq $newArr) { $newArr = @() } else { $newArr = @($newArr) }

        $oldMap = @{}
        $oldLabel = @{}
        foreach ($it in $oldArr) {
            $k = Get-ResourceKey $t $it
            $oldMap[$k] = ConvertTo-PlainObject $it
            $oldLabel[$k] = Get-ResourceLabel $t $it
        }
        $newMap = @{}
        $newLabel = @{}
        foreach ($it in $newArr) {
            $k = Get-ResourceKey $t $it
            $newMap[$k] = ConvertTo-PlainObject $it
            $newLabel[$k] = Get-ResourceLabel $t $it
        }

        $added = New-Object System.Collections.ArrayList
        $removed = New-Object System.Collections.ArrayList
        $changed = New-Object System.Collections.ArrayList

        foreach ($k in $newMap.Keys) {
            if (-not $oldMap.ContainsKey($k)) {
                [void]$added.Add([pscustomobject]@{ Key = $k; Label = $newLabel[$k] })
            }
            else {
                $oldJson = $oldMap[$k] | ConvertTo-Json -Depth 30 -Compress
                $newJson = $newMap[$k] | ConvertTo-Json -Depth 30 -Compress
                if ($oldJson -ne $newJson) {
                    $paths = @(Get-ChangedPaths -Old $oldMap[$k] -New $newMap[$k] -Path "")
                    [void]$changed.Add([pscustomobject]@{ Key = $k; Label = $newLabel[$k]; Changes = $paths })
                }
            }
        }
        foreach ($k in $oldMap.Keys) {
            if (-not $newMap.ContainsKey($k)) {
                [void]$removed.Add([pscustomobject]@{ Key = $k; Label = $oldLabel[$k] })
            }
        }

        $diffResult[$t] = [pscustomobject]@{
            Added   = @($added)
            Removed = @($removed)
            Changed = @($changed)
        }
    }

    if ($Json) {
        $jsonObj = [pscustomobject]@{
            old  = $Diff[0]
            new  = $Diff[1]
            diff = $diffResult
        }
        Write-ReportText ($jsonObj | ConvertTo-Json -Depth 10)
    }
    else {
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add("Drift report")
        [void]$lines.Add("  old: $($Diff[0])")
        [void]$lines.Add("  new: $($Diff[1])")
        [void]$lines.Add("")
        foreach ($t in $types) {
            $d = $diffResult[$t]
            [void]$lines.Add("[$t] +$($d.Added.Count) -$($d.Removed.Count) ~$($d.Changed.Count)")
            foreach ($a in $d.Added) { [void]$lines.Add("  + $($a.Label) ($($a.Key))") }
            foreach ($r in $d.Removed) { [void]$lines.Add("  - $($r.Label) ($($r.Key))") }
            foreach ($c in $d.Changed) { [void]$lines.Add("  ~ $($c.Label) ($($c.Key)): $($c.Changes -join '; ')") }
        }
        Write-ReportText ($lines -join "`n")
    }
    exit 0
}

# =============================================================================
# -List mode (default)
# =============================================================================
$files = @()
if (Test-Path $SnapshotDir) {
    $files = @(Get-ChildItem -Path $SnapshotDir -Filter "*.json" -File -ErrorAction SilentlyContinue | Sort-Object -Property Name -Descending)
}
$rows = New-Object System.Collections.ArrayList
foreach ($f in $files) {
    [void]$rows.Add([pscustomobject]@{
        File          = $f.Name
        LastWriteTime = $f.LastWriteTime
        SizeKB        = [int]($f.Length / 1KB)
    })
}

if ($Json) {
    Write-ReportText (@($rows) | ConvertTo-Json -Depth 5)
}
else {
    if ($Output) { @($rows) | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -LiteralPath $Output -Encoding utf8 }
    @($rows) | Format-Table -AutoSize
}
