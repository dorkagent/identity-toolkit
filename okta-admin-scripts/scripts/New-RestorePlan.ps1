<#
.SYNOPSIS
    Generates a dependency-ordered, human-reviewed restore plan from an Okta config backup (WhatIf only).

.DESCRIPTION
    OFFLINE. Reads a JSON config backup file and produces a dependency-ordered
    restore plan: groups, then zones and authenticators, then policies and
    rules, then apps, then assignments. The plan is WhatIf output -- the script
    applies nothing and makes zero HTTP calls to the Okta tenant.

    The shared OktaClient module is imported for repo consistency only; no
    client is created (New-OktaClient would throw without OKTA_DOMAIN /
    OKTA_API_TOKEN, and this script needs neither), and no API call is ever
    made.

    Every destructive or irreversible step is flagged NeedsApproval=$true:
      - policy rules: "review: mis-ordered or over-broad policy restore can
        lock out admins"
      - authenticator creates/changes: they alter MFA enrollment and sign-in
        security posture
      - any entry the backup marks for deletion or deactivation

    Resources the plan cannot handle (unknown top-level keys, entries with
    neither name nor id) are collected into an "Unsupported" section that is
    always printed -- never silently skipped.

    ACCEPTED BACKUP FORMAT (a JSON object; every top-level key is optional,
    missing keys are tolerated and their phase is emitted empty and noted):
    {
      "groups":         [ { "id": "...", "name": "...", "description": "..." } ],
      "zones":          [ { "id": "...", "name": "...", "status": "...", "gateways": [ ... ] } ],
      "authenticators": [ { "id": "...", "name": "...", "type": "...", "status": "..." } ],
      "policies":       [ { "id": "...", "name": "...", "type": "...", "status": "...",
                            "rules": [ { "id": "...", "name": "...", "status": "...",
                                         "conditions": { ... }, "actions": { ... } } ] } ],
      "apps":           [ { "id": "...", "name": "...", "label": "...", "status": "..." } ],
      "assignments":    [ { "appName": "...", "appId": "...",
                            "userIds": [ "..." ], "logins": [ "..." ],
                            "groupIds": [ "..." ], "groups": [ "..." ] } ]
    }
    Entries are plain objects needing at least a name (or label) or an id.
    An entry whose status is DELETED/DEACTIVATED (or that carries a deleted /
    remove / deactivate / action:"delete|deactivate" marker) is planned as a
    Delete/Deactivate step and flagged for approval.

.PARAMETER BackupPath
    Path to the JSON config backup file.

.PARAMETER Json
    Emit the structured plan object as JSON instead of markdown.

.PARAMETER Output
    Write the report to the given file path (markdown, or JSON with -Json).
    The console output is always printed as well.

.EXAMPLE
    pwsh ./New-RestorePlan.ps1 -BackupPath ./backup-2026-09-28.json
    Prints the markdown restore plan, with approval gates listed first.

.EXAMPLE
    pwsh ./New-RestorePlan.ps1 -BackupPath ./backup.json -Json -Output plan.json
    Writes the structured plan as JSON to plan.json.

.EXAMPLE
    pwsh ./New-RestorePlan.ps1 -BackupPath ./backup.json -Output plan.md
    Writes the markdown plan to plan.md.
#>

param(
    [Parameter(Mandatory)][string]$BackupPath,
    [switch]$Json,
    [string]$Output
)

# OFFLINE BY DESIGN. The shared module is imported for repo consistency only.
# No client is created and no HTTP call is ever made, so OKTA_DOMAIN and
# OKTA_API_TOKEN are not required.
Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force

$script:Steps = @()
$script:NextStep = 1
$script:Unsupported = @()
$script:MissingSections = @()

function New-PlanStep {
    <#
    .SYNOPSIS
        Append one ordered step to the plan and return it.
    #>
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [int[]]$DependsOn = @(),
        [bool]$NeedsApproval = $false,
        [string]$ApprovalReason = '',
        [string]$Note = ''
    )
    $step = [pscustomobject]@{
        Step           = $script:NextStep
        Phase          = $Phase
        Action         = $Action
        Target         = $Target
        DependsOn      = @($DependsOn | Sort-Object -Unique)
        NeedsApproval  = $NeedsApproval
        ApprovalReason = $ApprovalReason
        Note           = $Note
    }
    $script:Steps += $step
    $script:NextStep++
    return $step
}

function Add-Unsupported {
    <#
    .SYNOPSIS
        Record something the plan cannot handle. Always reported, never dropped.
    #>
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Detail
    )
    $script:Unsupported += [pscustomobject]@{ Source = $Source; Detail = $Detail }
}

function Get-EntryNames {
    <#
    .SYNOPSIS
        All usable names for a backup entry (name, label, title, or the string itself).
    #>
    param([Parameter(Mandatory)][psobject]$Entry)
    if ($Entry -is [string]) { return @($Entry) }
    $names = @()
    foreach ($key in @('name', 'label', 'title')) {
        $value = $Entry.$key
        if ($value -is [string] -and $value -and $names -notcontains $value) { $names += $value }
    }
    return @($names)
}

function Get-EntryName {
    <#
    .SYNOPSIS
        Best display name for a backup entry (first of name, label, title, or the string itself).
    #>
    param([Parameter(Mandatory)][psobject]$Entry)
    # @( ) re-wraps: a single name would otherwise arrive as a scalar string,
    # and $names[0] on a string returns its first *character*.
    $names = @(Get-EntryNames -Entry $Entry)
    if ($names.Count -gt 0) { return $names[0] }
    return ''
}

function Get-EntryId {
    <#
    .SYNOPSIS
        The id of a backup entry, or '' when it has none.
    #>
    param([Parameter(Mandatory)][psobject]$Entry)
    if ($Entry -is [pscustomobject]) { return [string]$Entry.id }
    return ''
}

function Get-DisplayTarget {
    <#
    .SYNOPSIS
        "Name (id)", "Name", "id", or '' for a backup entry.
    #>
    param([Parameter(Mandatory)][psobject]$Entry)
    $name = Get-EntryName -Entry $Entry
    $id = Get-EntryId -Entry $Entry
    if ($name -and $id) { return "$name ($id)" }
    if ($name) { return $name }
    if ($id) { return $id }
    return ''
}

function Get-StepTarget {
    <#
    .SYNOPSIS
        The Target text of an already-planned step, or '' when not found.
    #>
    param([Parameter(Mandatory)][int]$StepNumber)
    $found = $script:Steps | Where-Object { $_.Step -eq $StepNumber } | Select-Object -First 1
    if ($null -ne $found) { return $found.Target }
    return ''
}

function Test-RemovalMarker {
    <#
    .SYNOPSIS
        Return 'Delete' or 'Deactivate' when the backup entry is marked for
        removal, otherwise $null.
    #>
    param([Parameter(Mandatory)][psobject]$Entry)
    if ($Entry -isnot [pscustomobject]) { return $null }
    $status = [string]$Entry.status
    if ($status -eq 'DELETED') { return 'Delete' }
    if ($status -eq 'DEACTIVATED') { return 'Deactivate' }
    foreach ($flag in @('deleted', 'remove', 'markedForDeletion')) {
        $flagValue = $Entry.$flag
        if ($flagValue -eq $true -or $flagValue -eq 'true') { return 'Delete' }
    }
    foreach ($flag in @('deactivate', 'deactivated')) {
        $flagValue = $Entry.$flag
        if ($flagValue -eq $true -or $flagValue -eq 'true') { return 'Deactivate' }
    }
    $action = [string]$Entry.action
    if ($action -eq 'delete') { return 'Delete' }
    if ($action -eq 'deactivate') { return 'Deactivate' }
    return $null
}

function Get-EntryList {
    <#
    .SYNOPSIS
        First non-null list found under any of the given keys, always as an array.
    #>
    param(
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][string[]]$Keys
    )
    foreach ($key in $Keys) {
        $value = $Entry.$key
        if ($null -ne $value) { return @($value) }
    }
    return @()
}

function Get-PrincipalLabel {
    <#
    .SYNOPSIS
        Display label for a user/group reference (string, or object with name/id).
    #>
    param([Parameter(Mandatory)][psobject]$Ref)
    if ($Ref -is [string]) { return $Ref }
    $name = Get-EntryName -Entry $Ref
    if ($name) { return $name }
    $id = Get-EntryId -Entry $Ref
    if ($id) { return $id }
    return ''
}

function Add-ResourceStep {
    <#
    .SYNOPSIS
        Plan one backup entry as Create (or Delete/Deactivate when the backup
        marks it for removal). Returns the step, or $null when the entry is
        unsupported (recorded via Add-Unsupported).
    #>
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][psobject]$Entry,
        [Parameter(Mandatory)][string]$Ref,
        [int[]]$DependsOn = @(),
        [string]$Note = '',
        [bool]$AlwaysApprove = $false,
        [string]$AlwaysApproveReason = ''
    )
    $name = Get-EntryName -Entry $Entry
    $id = Get-EntryId -Entry $Entry
    if (-not $name -and -not $id) {
        Add-Unsupported -Source $Section -Detail "$Ref`: entry has neither name nor id -- skipped"
        return $null
    }
    $removal = Test-RemovalMarker -Entry $Entry
    $action = 'Create'
    $needsApproval = $AlwaysApprove
    $reason = $AlwaysApproveReason
    if ($removal) {
        $action = $removal
        $needsApproval = $true
        $removalReason = "marked for $removal in the backup -- confirm intent before restoring"
        if ($reason) { $reason = "$removalReason; $reason" } else { $reason = $removalReason }
    }
    return (New-PlanStep -Phase $Phase -Action $action -Target (Get-DisplayTarget -Entry $Entry) -DependsOn $DependsOn -NeedsApproval $needsApproval -ApprovalReason $reason -Note $Note)
}

function Get-SectionEntries {
    <#
    .SYNOPSIS
        Entries for one backup top-level key; tolerates missing keys and
        reports non-array values as unsupported.
    #>
    param([Parameter(Mandatory)][string]$Key)
    if ($backup.PSObject.Properties.Name -notcontains $Key) {
        $script:MissingSections += $Key
        return @()
    }
    $value = $backup.$Key
    if ($null -eq $value) { return @() }
    if ($value -is [string] -or $value -isnot [System.Collections.IEnumerable]) {
        Add-Unsupported -Source $Key -Detail "expected an array of entries, got a scalar value -- skipped"
        return @()
    }
    return @($value)
}

function ConvertTo-MdCell {
    <#
    .SYNOPSIS
        Make text safe for a markdown table cell.
    #>
    param([Parameter(Mandatory)][string]$Text)
    $t = $Text -replace '\|', '\|'
    $t = $t -replace "`r`n", ' '
    return ($t -replace "`n", ' ')
}

function Format-StepDeps {
    <#
    .SYNOPSIS
        "step 1, step 4" or "none" for a DependsOn array.
    #>
    param([int[]]$StepNumbers = @())
    if ($StepNumbers.Count -eq 0) { return 'none' }
    return 'step ' + ($StepNumbers -join ', step ')
}

# ---- Read and validate the backup -------------------------------------------

if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
    throw "Backup file not found: $BackupPath"
}
$raw = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop
try {
    $backup = $raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Backup file is not valid JSON: $($_.Exception.Message)"
}
if ($backup -isnot [pscustomobject]) {
    throw "Backup JSON must be an object with top-level arrays (groups, zones, ...), not a top-level array or scalar."
}

$knownKeys = @('groups', 'zones', 'authenticators', 'policies', 'apps', 'assignments')
$presentKeys = @($backup.PSObject.Properties.Name | Where-Object { $_ })
foreach ($key in $presentKeys) {
    if ($key -in $knownKeys) { continue }
    $value = $backup.$key
    $shape = 'scalar value'
    if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
        $shape = "$((@($value)).Count) entries"
    }
    Add-Unsupported -Source $key -Detail "unknown top-level key '$key' ($shape) -- not understood; not planned"
}

# ---- Phase 1: Groups --------------------------------------------------------

$groupStepById = @{}
$groupStepByName = @{}
$index = 0
foreach ($entry in (Get-SectionEntries -Key 'groups')) {
    $index++
    $step = Add-ResourceStep -Section 'groups' -Phase 'Groups' -Entry $entry -Ref "groups[$index]" -Note 'Restore first: policies, rules and assignments later in the plan can reference groups.'
    if ($null -ne $step) {
        $entryId = Get-EntryId -Entry $entry
        if ($entryId) { $groupStepById[$entryId] = $step.Step }
        foreach ($entryName in (Get-EntryNames -Entry $entry)) { $groupStepByName[$entryName] = $step.Step }
    }
}

# ---- Phase 2: Zones and Authenticators ---------------------------------------

$zoneStepById = @{}
$zoneStepByName = @{}
$index = 0
foreach ($entry in (Get-SectionEntries -Key 'zones')) {
    $index++
    $step = Add-ResourceStep -Section 'zones' -Phase 'ZonesAndAuthenticators' -Entry $entry -Ref "zones[$index]" -Note 'Zones restore in phase 2 so policy network conditions can resolve to them.'
    if ($null -ne $step) {
        $entryId = Get-EntryId -Entry $entry
        if ($entryId) { $zoneStepById[$entryId] = $step.Step }
        foreach ($entryName in (Get-EntryNames -Entry $entry)) { $zoneStepByName[$entryName] = $step.Step }
    }
}
$index = 0
foreach ($entry in (Get-SectionEntries -Key 'authenticators')) {
    $index++
    $null = Add-ResourceStep -Section 'authenticators' -Phase 'ZonesAndAuthenticators' -Entry $entry -Ref "authenticators[$index]" -AlwaysApprove $true -AlwaysApproveReason 'authenticator changes alter MFA enrollment and sign-in security posture -- review before applying' -Note 'Authenticators restore in phase 2, before the policies that may require them.'
}

function Get-ReferencedSteps {
    <#
    .SYNOPSIS
        Step numbers of group/zone steps whose id or name appears in the given
        JSON text (used to wire policy dependencies).
    #>
    param([Parameter(Mandatory)][string]$JsonText)
    $hits = @()
    foreach ($k in $groupStepById.Keys) { if ($JsonText.Contains("`"$k`"")) { $hits += $groupStepById[$k] } }
    foreach ($k in $groupStepByName.Keys) { if ($JsonText.Contains("`"$k`"")) { $hits += $groupStepByName[$k] } }
    foreach ($k in $zoneStepById.Keys) { if ($JsonText.Contains("`"$k`"")) { $hits += $zoneStepById[$k] } }
    foreach ($k in $zoneStepByName.Keys) { if ($JsonText.Contains("`"$k`"")) { $hits += $zoneStepByName[$k] } }
    return @($hits | Sort-Object -Unique)
}

# ---- Phase 3: Policies and Rules ---------------------------------------------

$index = 0
foreach ($policy in (Get-SectionEntries -Key 'policies')) {
    $index++
    $policyJson = ''
    if ($policy -is [pscustomobject]) { $policyJson = ($policy | ConvertTo-Json -Depth 20 -Compress) }
    $refSteps = @()
    if ($policyJson) { $refSteps = Get-ReferencedSteps -JsonText $policyJson }
    $depNote = 'Phase order already restores groups and zones first; no direct group/zone references detected in this policy.'
    if ($refSteps.Count -gt 0) {
        $depNote = "References groups/zones restored in step(s) $($refSteps -join ', ') -- restore those first."
    }
    $policyStep = Add-ResourceStep -Section 'policies' -Phase 'PoliciesAndRules' -Entry $policy -Ref "policies[$index]" -DependsOn $refSteps -Note $depNote
    if ($null -eq $policyStep) { continue }
    $policyName = Get-EntryName -Entry $policy
    if (-not $policyName) { $policyName = Get-EntryId -Entry $policy }
    $rules = @()
    if ($policy -is [pscustomobject] -and $null -ne $policy.rules) {
        if ($policy.rules -is [System.Collections.IEnumerable] -and $policy.rules -isnot [string]) {
            $rules = @($policy.rules)
        } else {
            Add-Unsupported -Source 'policies' -Detail "policies[$index]: 'rules' is not an array -- skipped"
        }
    }
    $ruleIndex = 0
    foreach ($rule in $rules) {
        $ruleIndex++
        $null = Add-ResourceStep -Section 'policies' -Phase 'PoliciesAndRules' -Entry $rule -Ref "policies[$index].rules[$ruleIndex]" -DependsOn @($policyStep.Step) -AlwaysApprove $true -AlwaysApproveReason 'review: mis-ordered or over-broad policy restore can lock out admins' -Note "Rule of policy '$policyName'; restores only after its policy (step $($policyStep.Step))."
    }
}

# ---- Phase 4: Apps -----------------------------------------------------------

$appStepById = @{}
$appStepByName = @{}
$removedAppSteps = @()
$index = 0
foreach ($entry in (Get-SectionEntries -Key 'apps')) {
    $index++
    $step = Add-ResourceStep -Section 'apps' -Phase 'Apps' -Entry $entry -Ref "apps[$index]" -Note 'Apps restore after policies so the sign-on policies that govern them already exist.'
    if ($null -ne $step) {
        $entryId = Get-EntryId -Entry $entry
        if ($entryId) { $appStepById[$entryId] = $step.Step }
        foreach ($entryName in (Get-EntryNames -Entry $entry)) { $appStepByName[$entryName] = $step.Step }
        if (Test-RemovalMarker -Entry $entry) { $removedAppSteps += $step.Step }
    }
}

# ---- Phase 5: Assignments -----------------------------------------------------

function Resolve-GroupStep {
    <#
    .SYNOPSIS
        Step number of the group step matching a group id or name reference, or $null.
    #>
    param([Parameter(Mandatory)][psobject]$Ref)
    if ($Ref -is [string]) {
        if ($groupStepById.ContainsKey($Ref)) { return $groupStepById[$Ref] }
        if ($groupStepByName.ContainsKey($Ref)) { return $groupStepByName[$Ref] }
        return $null
    }
    $refId = Get-EntryId -Entry $Ref
    if ($refId -and $groupStepById.ContainsKey($refId)) { return $groupStepById[$refId] }
    $refName = Get-EntryName -Entry $Ref
    if ($refName -and $groupStepByName.ContainsKey($refName)) { return $groupStepByName[$refName] }
    return $null
}

$index = 0
foreach ($assignment in (Get-SectionEntries -Key 'assignments')) {
    $index++
    if ($assignment -isnot [pscustomobject]) {
        Add-Unsupported -Source 'assignments' -Detail "assignments[$index]: not an object -- skipped"
        continue
    }
    $appId = ''
    if ($assignment.appId -is [string]) { $appId = $assignment.appId }
    $appName = ''
    foreach ($k in @('appName', 'app', 'name', 'label')) {
        $candidate = $assignment.$k
        if ($candidate -is [string] -and $candidate) { $appName = $candidate; break }
    }
    $appLabel = $appName
    if (-not $appLabel) { $appLabel = $appId }
    if (-not $appLabel) { $appLabel = "(assignments[$index])" }
    $appStep = $null
    if ($appId -and $appStepById.ContainsKey($appId)) { $appStep = $appStepById[$appId] }
    elseif ($appName -and $appStepByName.ContainsKey($appName)) { $appStep = $appStepByName[$appName] }
    $appIsRemoved = ($null -ne $appStep) -and ($removedAppSteps -contains $appStep)
    $appTarget = $appLabel
    if ($null -ne $appStep) { $appTarget = Get-StepTarget -StepNumber $appStep }
    $users = Get-EntryList -Entry $assignment -Keys @('userIds', 'users', 'logins', 'userLogins')
    $assignGroups = Get-EntryList -Entry $assignment -Keys @('groupIds', 'groups', 'groupNames')
    if ($users.Count -eq 0 -and $assignGroups.Count -eq 0) {
        Add-Unsupported -Source 'assignments' -Detail "assignments[$index]: no userIds/logins/groupIds/groups -- nothing to assign"
        continue
    }
    foreach ($u in $users) {
        $userLabel = Get-PrincipalLabel -Ref $u
        if (-not $userLabel) {
            Add-Unsupported -Source 'assignments' -Detail "assignments[$index]: a user reference has no usable id or login -- skipped"
            continue
        }
        $deps = @()
        $note = "Assign user '$userLabel' to app '$appTarget'."
        if ($null -ne $appStep) {
            $deps += $appStep
            $note += " Restore the app first (step $appStep)."
        } else {
            $note += ' App not found in backup -- verify it exists in the tenant before assigning.'
        }
        $needsApproval = $false
        $reason = ''
        if ($appIsRemoved) {
            $needsApproval = $true
            $reason = "references app '$appTarget', which is marked for deletion/deactivation in the backup -- confirm intent"
        }
        $null = New-PlanStep -Phase 'Assignments' -Action 'Assign' -Target "User '$userLabel' -> app '$appTarget'" -DependsOn $deps -NeedsApproval $needsApproval -ApprovalReason $reason -Note $note
    }
    foreach ($g in $assignGroups) {
        $groupLabel = Get-PrincipalLabel -Ref $g
        if (-not $groupLabel) {
            Add-Unsupported -Source 'assignments' -Detail "assignments[$index]: a group reference has no usable id or name -- skipped"
            continue
        }
        $groupStep = Resolve-GroupStep -Ref $g
        $groupTarget = $groupLabel
        if ($null -ne $groupStep) { $groupTarget = Get-StepTarget -StepNumber $groupStep }
        $deps = @()
        $note = "Assign group '$groupTarget' to app '$appTarget'."
        $missing = @()
        if ($null -ne $appStep) { $deps += $appStep } else { $missing += 'app' }
        if ($null -ne $groupStep) { $deps += $groupStep } else { $missing += 'group' }
        if ($missing.Count -eq 0) {
            $note += " Restore the app (step $appStep) and the group (step $groupStep) first."
        } else {
            $note += " Not in backup ($($missing -join ' and ')) -- verify it exists in the tenant before assigning."
        }
        $needsApproval = $false
        $reason = ''
        if ($appIsRemoved) {
            $needsApproval = $true
            $reason = "references app '$appTarget', which is marked for deletion/deactivation in the backup -- confirm intent"
        }
        $null = New-PlanStep -Phase 'Assignments' -Action 'Assign' -Target "Group '$groupTarget' -> app '$appTarget'" -DependsOn $deps -NeedsApproval $needsApproval -ApprovalReason $reason -Note $note
    }
}

# ---- Assemble the plan --------------------------------------------------------

$approvalSteps = @($script:Steps | Where-Object { $_.NeedsApproval })
$plan = [pscustomobject]@{
    generatedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    sourceFile     = $BackupPath
    whatIf         = $true
    appliesNothing = $true
    phaseOrder     = @('Groups', 'ZonesAndAuthenticators', 'PoliciesAndRules', 'Apps', 'Assignments')
    summary        = [pscustomobject]@{
        totalSteps    = $script:Steps.Count
        approvalGates = $approvalSteps.Count
        unsupported   = $script:Unsupported.Count
    }
    steps          = @($script:Steps)
    unsupported    = @($script:Unsupported)
}

# ---- Render -------------------------------------------------------------------

if ($Json) {
    $text = $plan | ConvertTo-Json -Depth 10
} else {
    $lines = @()
    $lines += '# Okta Config Restore Plan (WhatIf -- applies nothing)'
    $lines += ''
    $lines += "- Source backup: ``$BackupPath``"
    $lines += "- Generated (UTC): $($plan.generatedUtc)"
    $lines += "- Steps: $($plan.summary.totalSteps) | Approval gates: $($plan.summary.approvalGates) | Unsupported: $($plan.summary.unsupported)"
    $lines += ''
    $lines += '> **WhatIf only.** This plan was generated offline from a backup file. It makes'
    $lines += '> zero HTTP calls and changes nothing in the tenant. A human reviews every step'
    $lines += '> below and applies it by hand (or not).'
    $lines += ''
    $lines += "## REQUIRES HUMAN APPROVAL -- DO NOT APPLY WITHOUT REVIEW ($($approvalSteps.Count))"
    $lines += ''
    if ($approvalSteps.Count -eq 0) {
        $lines += 'None. No destructive or irreversible steps were detected.'
    } else {
        $lines += '| Step | Phase | Action | Target | Why approval is required |'
        $lines += '| --- | --- | --- | --- | --- |'
        foreach ($s in $approvalSteps) {
            $lines += "| $($s.Step) | $(ConvertTo-MdCell -Text $s.Phase) | $(ConvertTo-MdCell -Text $s.Action) | $(ConvertTo-MdCell -Text $s.Target) | $(ConvertTo-MdCell -Text $s.ApprovalReason) |"
        }
    }
    $lines += ''
    $phaseMeta = @(
        @{ Key = 'Groups'; Title = 'Phase 1 -- Groups'; Sections = @('groups') },
        @{ Key = 'ZonesAndAuthenticators'; Title = 'Phase 2 -- Zones and Authenticators'; Sections = @('zones', 'authenticators') },
        @{ Key = 'PoliciesAndRules'; Title = 'Phase 3 -- Policies and Rules'; Sections = @('policies') },
        @{ Key = 'Apps'; Title = 'Phase 4 -- Apps'; Sections = @('apps') },
        @{ Key = 'Assignments'; Title = 'Phase 5 -- Assignments'; Sections = @('assignments') }
    )
    foreach ($pm in $phaseMeta) {
        $phaseSteps = @($script:Steps | Where-Object { $_.Phase -eq $pm.Key })
        $lines += "## $($pm.Title) ($($phaseSteps.Count) steps)"
        $lines += ''
        if ($phaseSteps.Count -eq 0) {
            $missingHere = @($pm.Sections | Where-Object { $script:MissingSections -contains $_ })
            if ($missingHere.Count -eq $pm.Sections.Count) {
                $lines += 'No entries in backup -- phase skipped (tolerated).'
            } else {
                $lines += 'No plannable entries -- see the Unsupported section.'
            }
        } else {
            $lines += '| Step | Action | Target | Depends on | Needs approval | Note |'
            $lines += '| --- | --- | --- | --- | --- | --- |'
            foreach ($s in $phaseSteps) {
                $flag = 'no'
                if ($s.NeedsApproval) { $flag = '**YES**' }
                $lines += "| $($s.Step) | $(ConvertTo-MdCell -Text $s.Action) | $(ConvertTo-MdCell -Text $s.Target) | $(Format-StepDeps -StepNumbers $s.DependsOn) | $flag | $(ConvertTo-MdCell -Text $s.Note) |"
            }
        }
        $lines += ''
    }
    $lines += "## Unsupported -- reported, never skipped ($($script:Unsupported.Count))"
    $lines += ''
    if ($script:Unsupported.Count -eq 0) {
        $lines += 'None. Every top-level key and entry was understood.'
    } else {
        foreach ($u in $script:Unsupported) {
            $lines += "- **$(ConvertTo-MdCell -Text $u.Source)**: $(ConvertTo-MdCell -Text $u.Detail)"
        }
    }
    $text = $lines -join [Environment]::NewLine
}

if ($text) { Write-Output $text }
if ($Output) { $text | Out-File -FilePath $Output -Encoding utf8 }
