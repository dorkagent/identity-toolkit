<#
.SYNOPSIS
    Joiner/Mover/Leaver (JML) lifecycle automation kit for Okta. (DHQ-86)

.DESCRIPTION
    Drives user lifecycle changes from a CSV file. Columns: login, firstName,
    lastName, email (optional, falls back to login), groups (semicolon-separated
    group names), apps (semicolon-separated app labels).

    Modes:
      joiner - Create the user (activate=false) when missing, otherwise update
               the profile when it differs; add group memberships and app
               assignments that are missing.
      mover   - Update the profile; add missing group/app memberships; remove
               extras ONLY when -Prune is also given.
      leaver  - Deactivate the user via the lifecycle API and report remaining
               app assignments and group memberships.

    DRY-RUN BY DEFAULT: without -Apply the script only reports what WOULD
    change. Every check is idempotent: already-correct state is skipped.

    Authentication comes from the OKTA_DOMAIN / OKTA_API_TOKEN environment
    variables only.

.PARAMETER Mode
    Required. One of: joiner, mover, leaver.

.PARAMETER Csv
    Required. Path to the input CSV file.

.PARAMETER Apply
    Execute the changes. Without -Apply this is a dry run (report only).

.PARAMETER Prune
    Mover mode only: remove group memberships and app assignments that are not
    listed in the CSV row. Without -Prune, extras are reported and kept.

.PARAMETER Json
    Emit the report as JSON instead of a summary table.

.PARAMETER Output
    Write the report to this file path (JSON with -Json, CSV otherwise).

.EXAMPLE
    .\JML-AutomationKit.ps1 -Mode joiner -Csv .\new-hires.csv

    Dry run: report what creating/updating the new hires would change.

.EXAMPLE
    .\JML-AutomationKit.ps1 -Mode mover -Csv .\transfers.csv -Apply -Prune

    Apply a mover: update profiles, add missing memberships, prune extras.

.EXAMPLE
    .\JML-AutomationKit.ps1 -Mode leaver -Csv .\exits.csv -Apply -Json -Output .\leaver-report.json

    Deactivate exiting users and write a JSON report of remaining assignments.
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('joiner', 'mover', 'leaver')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$Csv,
    [switch]$Apply,
    [switch]$Prune,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

$ErrorActionPreference = 'Stop'

# Per-row accumulators (reset for every CSV row).
$script:rowLog = @()
$script:rowChanged = $false
$script:rowRemainingApps = @()
$script:rowRemainingGroups = @()

function Add-RowLog {
    param([string]$Message, [switch]$NoChange)
    $script:rowLog += $Message
    if (-not $NoChange) { $script:rowChanged = $true }
}

function Split-List {
    param([string]$Value)
    $out = @()
    if ($Value) {
        foreach ($part in ($Value -split ';')) {
            $t = $part.Trim()
            if ($t) { $out += $t }
        }
    }
    return $out
}

function Find-GroupExact {
    param([string]$Name)
    $cands = @(Get-OktaGroups -Client $client -Query $Name)
    foreach ($g in $cands) {
        if ([string]$g.name -eq $Name) { return $g }
    }
    return $null
}

function Find-AppExact {
    param([string]$Label)
    foreach ($a in $script:allApps) {
        if ([string]$a.label -eq $Label) { return $a }
    }
    return $null
}

function Test-GroupMembership {
    param([string]$GroupId, [string]$UserId)
    try {
        $null = Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/groups/$GroupId/users/$UserId"
        return $true
    } catch {
        if ($_.Exception.Message -match '404') { return $false }
        throw
    }
}

function Test-AppAssignment {
    param([string]$AppId, [string]$UserId)
    try {
        $null = Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/apps/$AppId/users/$UserId"
        return $true
    } catch {
        if ($_.Exception.Message -match '404') { return $false }
        throw
    }
}

function Add-GroupMember {
    param([string]$GroupName, [string]$UserId)
    $g = Find-GroupExact -Name $GroupName
    if (-not $g) {
        Add-RowLog -Message "Group not found: $GroupName" -NoChange
        return
    }
    if (Test-GroupMembership -GroupId ([string]$g.id) -UserId $UserId) {
        Add-RowLog -Message "Already member of group: $GroupName" -NoChange
        return
    }
    if ($Apply) {
        $null = Invoke-OktaRequest -Client $client -Method POST -Path "/api/v1/groups/$($g.id)/users/$UserId" -Body @{}
        Add-RowLog -Message "Added to group: $GroupName"
    } else {
        Add-RowLog -Message "Would add to group: $GroupName"
    }
}

function Add-AppAssignment {
    param([string]$AppLabel, [string]$UserId)
    $a = Find-AppExact -Label $AppLabel
    if (-not $a) {
        Add-RowLog -Message "App not found: $AppLabel" -NoChange
        return
    }
    if (Test-AppAssignment -AppId ([string]$a.id) -UserId $UserId) {
        Add-RowLog -Message "Already assigned app: $AppLabel" -NoChange
        return
    }
    if ($Apply) {
        $null = Invoke-OktaRequest -Client $client -Method POST -Path "/api/v1/apps/$($a.id)/users" -Body @{ id = $UserId }
        Add-RowLog -Message "Assigned app: $AppLabel"
    } else {
        Add-RowLog -Message "Would assign app: $AppLabel"
    }
}

function Sync-UserProfile {
    param($User, $Row, [string]$Email)
    $changes = @()
    if ([string]$User.profile.firstName -ne [string]$Row.firstName) { $changes += "firstName" }
    if ([string]$User.profile.lastName -ne [string]$Row.lastName) { $changes += "lastName" }
    if ([string]$User.profile.email -ne $Email) { $changes += "email" }
    if ($changes.Count -eq 0) {
        Add-RowLog -Message "Profile already up to date" -NoChange
        return
    }
    $uid = [string]$User.id
    if ($Apply) {
        $body = @{ profile = @{
            firstName = [string]$Row.firstName
            lastName  = [string]$Row.lastName
            email     = $Email
            login     = [string]$Row.login
        } }
        $null = Invoke-OktaRequest -Client $client -Method PUT -Path "/api/v1/users/$uid" -Body $body
        Add-RowLog -Message ("Updated profile: " + ($changes -join ", "))
    } else {
        Add-RowLog -Message ("Would update profile: " + ($changes -join ", "))
    }
}

if (-not (Test-Path $Csv)) { throw "CSV file not found: $Csv" }
if (-not $Apply) {
    Write-Warning "Dry run: no changes will be applied. Use -Apply to execute."
}

$csvRows = @(Import-Csv -Path $Csv)
$script:allApps = @(Get-OktaApps -Client $client)

$details = @()
foreach ($r in $csvRows) {
    $script:rowLog = @()
    $script:rowChanged = $false
    $script:rowRemainingApps = @()
    $script:rowRemainingGroups = @()

    $login = [string]$r.login
    if (-not $login) {
        $details += [pscustomobject]@{
            Login           = "(missing)"
            Mode            = $Mode
            Status          = "Skipped"
            Actions         = @("Row has no login; skipped")
            RemainingApps   = @()
            RemainingGroups = @()
        }
        continue
    }
    $email = [string]$r.email
    if (-not $email) { $email = $login }
    $desiredGroups = @(Split-List -Value ([string]$r.groups))
    $desiredApps = @(Split-List -Value ([string]$r.apps))

    $user = Get-OktaUserByLogin -Client $client -Login $login

    if ($Mode -eq 'joiner') {
        if (-not $user) {
            if ($Apply) {
                $body = @{ profile = @{
                    firstName = [string]$r.firstName
                    lastName  = [string]$r.lastName
                    email     = $email
                    login     = $login
                } }
                $user = Invoke-OktaRequest -Client $client -Method POST -Path "/api/v1/users?activate=false" -Body $body
                Add-RowLog -Message "Created user (activate=false)"
            } else {
                Add-RowLog -Message "Would create user (activate=false)"
                foreach ($gn in $desiredGroups) { Add-RowLog -Message "Would add to group: $gn" }
                foreach ($an in $desiredApps) { Add-RowLog -Message "Would assign app: $an" }
            }
        }
        if ($user) {
            Sync-UserProfile -User $user -Row $r -Email $email
            $uid = [string]$user.id
            foreach ($gn in $desiredGroups) { Add-GroupMember -GroupName $gn -UserId $uid }
            foreach ($an in $desiredApps) { Add-AppAssignment -AppLabel $an -UserId $uid }
        }
    } elseif ($Mode -eq 'mover') {
        if (-not $user) {
            Add-RowLog -Message "User not found; mover requires an existing user" -NoChange
        } else {
            Sync-UserProfile -User $user -Row $r -Email $email
            $uid = [string]$user.id
            foreach ($gn in $desiredGroups) { Add-GroupMember -GroupName $gn -UserId $uid }
            foreach ($an in $desiredApps) { Add-AppAssignment -AppLabel $an -UserId $uid }

            $currentGroups = @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/users/$uid/groups")
            foreach ($cg in $currentGroups) {
                if ($desiredGroups -notcontains [string]$cg.name) {
                    if ($Prune) {
                        if ($Apply) {
                            $null = Invoke-OktaRequest -Client $client -Method DELETE -Path "/api/v1/groups/$($cg.id)/users/$uid"
                            Add-RowLog -Message "Removed from extra group: $($cg.name)"
                        } else {
                            Add-RowLog -Message "Would remove from extra group: $($cg.name)"
                        }
                    } else {
                        Add-RowLog -Message "Extra group kept (use -Prune to remove): $($cg.name)" -NoChange
                    }
                }
            }

            $currentApps = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/apps' -Query @{'filter'="user.id eq `"$uid`""})
            foreach ($ca in $currentApps) {
                if ($desiredApps -notcontains [string]$ca.label) {
                    if ($Prune) {
                        if ($Apply) {
                            $null = Invoke-OktaRequest -Client $client -Method DELETE -Path "/api/v1/apps/$($ca.id)/users/$uid"
                            Add-RowLog -Message "Unassigned extra app: $($ca.label)"
                        } else {
                            Add-RowLog -Message "Would unassign extra app: $($ca.label)"
                        }
                    } else {
                        Add-RowLog -Message "Extra app kept (use -Prune to remove): $($ca.label)" -NoChange
                    }
                }
            }
        }
    } else {
        # leaver
        if (-not $user) {
            Add-RowLog -Message "User not found; nothing to deactivate" -NoChange
        } else {
            $uid = [string]$user.id
            if ([string]$user.status -ne 'ACTIVE') {
                Add-RowLog -Message "User already $($user.status); no deactivation needed" -NoChange
            } elseif ($Apply) {
                $null = Invoke-OktaRequest -Client $client -Method POST -Path "/api/v1/users/$uid/lifecycle/deactivate"
                Add-RowLog -Message "Deactivated user"
            } else {
                Add-RowLog -Message "Would deactivate user"
            }
            $remainingApps = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/apps' -Query @{'filter'="user.id eq `"$uid`""})
            $remainingGroups = @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/users/$uid/groups")
            $script:rowRemainingApps = @($remainingApps | ForEach-Object { [string]$_.label })
            $script:rowRemainingGroups = @($remainingGroups | ForEach-Object { [string]$_.name })
            if ($script:rowRemainingApps.Count -gt 0 -or $script:rowRemainingGroups.Count -gt 0) {
                Add-RowLog -Message ("Remaining assignments - apps: " + ($script:rowRemainingApps -join ", ") + "; groups: " + ($script:rowRemainingGroups -join ", ")) -NoChange
            } else {
                Add-RowLog -Message "No remaining app/group assignments" -NoChange
            }
        }
    }

    $status = "NoChange"
    if ($script:rowChanged) {
        if ($Apply) { $status = "Changed" } else { $status = "WouldChange" }
    }
    $details += [pscustomobject]@{
        Login           = $login
        Mode            = $Mode
        Status          = $status
        Actions         = @($script:rowLog)
        RemainingApps   = @($script:rowRemainingApps)
        RemainingGroups = @($script:rowRemainingGroups)
    }
}

$summary = @()
foreach ($d in $details) {
    $summary += [pscustomobject]@{
        Login   = $d.Login
        Mode    = $d.Mode
        Status  = $d.Status
        Changes = ($d.Actions -join '; ')
    }
}

if ($Json) {
    $report = ($details | ConvertTo-Json -Depth 10)
    Write-Output $report
    if ($Output) { $report | Out-File -FilePath $Output -Encoding utf8 }
} else {
    $summary | Format-Table -AutoSize -Wrap
    if ($Output) { $summary | Export-Csv -Path $Output -NoTypeInformation }
}
