#Requires -Version 7.0
<#
.SYNOPSIS
    Audits all Okta group rules for rot: broken, conflicting, or dead rules (read-only).

.DESCRIPTION
    Read-only. Enumerates every group rule (GET /api/v1/groups/rules) and flags:
      - InactiveRule:      status is INACTIVE (rule never evaluates).
      - InvalidRule:       status is INVALID (Okta cannot evaluate it).
      - EmptyExpression:   conditions.expression.value is missing or blank.
      - SuspiciousExpression: heuristic only; unbalanced quotes or
        parentheses in the expression. Labeled as heuristic in Evidence.
      - DeletedTargetGroup: a target group id 404s (the group was deleted after
        the rule was created). Each group lookup is isolated in try/catch so one
        bad group cannot abort the run.
      - EmptyTargetGroup:  a target group exists but has zero users.
      - DuplicateCondition: the same expression value is used by 2+ rules;
        Evidence names the sibling rules.
      - ConflictingTargets: 2+ ACTIVE rules assign users to the same target
        group; Evidence lists the sibling rules.

    With -ImpactPreview the script adds a MembersAtRisk column: the member count
    of each ACTIVE rule's target groups: roughly how many people a change to
    the rule would affect. Counts are summed across target groups, so a user
    in two target groups counts twice. Rows are ordered by MembersAtRisk,
    then by number of flags.

    Every call is a GET.

    Known gaps: ConflictingTargets also fires on the normal pattern of
    several rules feeding one group, and group IDs referenced inside rule
    expressions (isMemberOfAnyGroup("00g...")) are not checked yet.

.PARAMETER Limit
    Maximum number of group rules to audit. 0 (default) means all rules.

.PARAMETER ImpactPreview
    Add a MembersAtRisk column showing the member count of each ACTIVE rule's
    target groups, and order rows by it.

.PARAMETER Json
    Emit the report as JSON instead of a table.

.PARAMETER Output
    Write the report to the given file path. The report is JSON when -Json is
    used, otherwise CSV.

.EXAMPLE
    pwsh ./Test-GroupRule.ps1
    Audits all group rules and prints the findings table.

.EXAMPLE
    pwsh ./Test-GroupRule.ps1 -ImpactPreview
    Adds the MembersAtRisk column and orders by it.

.EXAMPLE
    pwsh ./Test-GroupRule.ps1 -Json -Output rules.json
    Writes the audit report as JSON to rules.json.

.EXAMPLE
    pwsh ./Test-GroupRule.ps1 -Limit 25 -Output rules.csv
    Audits up to 25 rules and writes the CSV report to rules.csv.
#>

param(
    [int]$Limit = 0,
    [switch]$ImpactPreview,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

# ---- Collect rules ---------------------------------------------------------
$rules = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/groups/rules')
if ($Limit -gt 0 -and $rules.Count -gt $Limit) { $rules = $rules[0..($Limit - 1)] }

# ---- First pass: per-rule data and cross-rule indexes ----------------------
$ruleInfos = @()
$byExpression = @{}   # normalized expression -> rule names (DuplicateCondition)
$activeTargets = @{}  # group id -> active rule names (ConflictingTargets)
$groupCache = @{}     # group id -> group object, or 'DELETED' / 'ERROR:<msg>'

foreach ($rule in $rules) {
    $name = [string]$rule.name
    if ([string]::IsNullOrWhiteSpace($name)) { $name = "(unnamed $($rule.id))" }
    $status = [string]$rule.status

    $expr = ''
    if ($null -ne $rule.conditions -and $null -ne $rule.conditions.expression) {
        $expr = [string]$rule.conditions.expression.value
    }

    $targetIds = @()
    if ($null -ne $rule.actions -and $null -ne $rule.actions.assignUserToGroups) {
        $targetIds = @($rule.actions.assignUserToGroups.groupIds) | Where-Object { $_ }
    }

    $flags = @()
    $evidence = @()

    if ($status -eq 'INACTIVE') {
        $flags += 'InactiveRule'
        $evidence += 'status=INACTIVE: rule never evaluates.'
    }
    if ($status -eq 'INVALID') {
        $flags += 'InvalidRule'
        $evidence += 'status=INVALID: Okta cannot evaluate this rule.'
    }
    if ([string]::IsNullOrWhiteSpace($expr)) {
        $flags += 'EmptyExpression'
        $evidence += 'conditions.expression.value is missing or blank.'
    } else {
        # Heuristic: unbalanced quotes or parentheses. Okta EL escapes quotes
        # as \", so strip those before counting. Never conclusive; labeled as
        # heuristic in the Evidence column.
        $quoteStripped = $expr -replace '\\"', ''
        $dbl = ([regex]::Matches($quoteStripped, '"')).Count
        $sgl = ([regex]::Matches($quoteStripped, "'")).Count
        $open = ([regex]::Matches($expr, '\(')).Count
        $close = ([regex]::Matches($expr, '\)')).Count
        if (($dbl % 2) -ne 0 -or ($sgl % 2) -ne 0 -or $open -ne $close) {
            $flags += 'SuspiciousExpression'
            $evidence += 'heuristic: expression has unbalanced quotes or parentheses; review manually.'
        }
    }

    $exprKey = $expr.Trim()
    if ($exprKey) {
        if (-not $byExpression.ContainsKey($exprKey)) { $byExpression[$exprKey] = @() }
        $byExpression[$exprKey] += $name
    }
    if ($status -eq 'ACTIVE') {
        foreach ($gid in $targetIds) {
            if (-not $activeTargets.ContainsKey($gid)) { $activeTargets[$gid] = @() }
            $activeTargets[$gid] += $name
        }
    }

    $ruleInfos += [pscustomobject]@{
        Name      = $name
        Status    = $status
        ExprKey   = $exprKey
        TargetIds = @($targetIds)
        Flags     = @($flags)
        Evidence  = @($evidence)
    }
}

# ---- Helper: cached, failure-isolated group lookup -------------------------
function Get-GroupCached {
    param([string]$GroupId)
    if ($groupCache.ContainsKey($GroupId)) { return $groupCache[$GroupId] }
    try {
        $g = Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/groups/$GroupId"
        $groupCache[$GroupId] = $g
        return $g
    } catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match '\b404\b') {
            $groupCache[$GroupId] = 'DELETED'
            return 'DELETED'
        }
        # Any other failure (auth, rate limit, network): do not kill the run.
        $groupCache[$GroupId] = "ERROR:$msg"
        return $groupCache[$GroupId]
    }
}

function Get-GroupMemberCount {
    param([string]$GroupId)
    # MembersAtRisk only needs a count; limit=200 pages keep traffic small while
    # Invoke-OktaPagedGet walks every page.
    try {
        $count = 0
        @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/groups/$GroupId/users" -Query @{ limit = 200 }) |
            ForEach-Object { $count++ }
        return $count
    } catch {
        return -1  # unknown: lookup failed, do not abort
    }
}

# ---- Second pass: group-dependent flags ------------------------------------
$memberCounts = @{}  # group id -> member count (only filled with -ImpactPreview)
foreach ($info in $ruleInfos) {
    $targetLabels = @()
    foreach ($gid in $info.TargetIds) {
        $g = Get-GroupCached -GroupId $gid
        if ($g -eq 'DELETED') {
            $info.Flags += 'DeletedTargetGroup'
            $info.Evidence += "target group $gid returns 404: it was deleted after the rule was created."
            $targetLabels += "DELETED:$gid"
            continue
        }
        if ($g -is [string] -and $g.StartsWith('ERROR:')) {
            $info.Evidence += "target group $gid could not be verified ($($g.Substring(6)))."
            $targetLabels += "$gid (unverified)"
            continue
        }
        $gname = [string]$g.profile.name
        if ([string]::IsNullOrWhiteSpace($gname)) { $gname = $gid }
        $targetLabels += $gname

        $memberCount = -1
        try {
            $users = @(Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/groups/$gid/users" -Query @{ limit = 1 })
            $memberCount = $users.Count
        } catch {
            $info.Evidence += "target group '$gname' member lookup failed: $($_.Exception.Message)"
        }
        if ($memberCount -eq 0) {
            $info.Flags += 'EmptyTargetGroup'
            $info.Evidence += "target group '$gname' exists but has zero users."
        }
    }

    # Cross-rule flags, resolved after the full first pass.
    if ($info.ExprKey) {
        $siblings = @($byExpression[$info.ExprKey]) | Where-Object { $_ -ne $info.Name }
        if ($siblings.Count -gt 0) {
            $info.Flags += 'DuplicateCondition'
            $info.Evidence += "same expression as: $($siblings -join ', ')."
        }
    }
    if ($info.Status -eq 'ACTIVE') {
        foreach ($gid in $info.TargetIds) {
            $rivals = @($activeTargets[$gid]) | Where-Object { $_ -ne $info.Name }
            if ($rivals.Count -gt 0) {
                $info.Flags += 'ConflictingTargets'
                $info.Evidence += "target group $gid is also assigned by active rule(s): $($rivals -join ', ')."
            }
        }
    }

    $info | Add-Member -NotePropertyName 'TargetLabels' -NotePropertyValue $targetLabels

    # MembersAtRisk: member count of each ACTIVE rule's target groups, summed
    # across the rule's live target groups (each group's member count; a user
    # in several target groups counts more than once). Non-active rules get 0.
    $risk = 0
    if ($ImpactPreview) {
        if ($info.Status -eq 'ACTIVE') {
            $seen = @{}
            foreach ($gid in $info.TargetIds) {
                if ($seen.ContainsKey($gid)) { continue }
                $seen[$gid] = $true
                $g = Get-GroupCached -GroupId $gid
                if ($g -eq 'DELETED' -or ($g -is [string] -and $g.StartsWith('ERROR:'))) { continue }
                if (-not $memberCounts.ContainsKey($gid)) {
                    $memberCounts[$gid] = Get-GroupMemberCount -GroupId $gid
                }
                if ($memberCounts[$gid] -ge 0) { $risk += $memberCounts[$gid] }
            }
        }
    }
    $info | Add-Member -NotePropertyName 'MembersAtRisk' -NotePropertyValue $risk
}

# ---- Build report rows (blast-radius ordered) -------------------------------
$rows = foreach ($info in $ruleInfos) {
    $flagsJoined = @($info.Flags | Select-Object -Unique) -join ','
    $props = [ordered]@{
        Rule         = $info.Name
        Status       = $info.Status
        Flags        = $flagsJoined
        TargetGroups = @($info.TargetLabels) -join ', '
    }
    if ($ImpactPreview) { $props['MembersAtRisk'] = $info.MembersAtRisk }
    $props['Evidence'] = @($info.Evidence) -join ' '
    $row = [pscustomobject]$props
    $row | Add-Member -NotePropertyName '_FlagCount' -NotePropertyValue (@($info.Flags | Select-Object -Unique).Count)
    $row | Add-Member -NotePropertyName '_Risk' -NotePropertyValue $info.MembersAtRisk
    $row
}

if ($ImpactPreview) {
    $rows = @($rows | Sort-Object -Property @{ Expression = { $_._Risk }; Descending = $true },
        @{ Expression = { $_._FlagCount }; Descending = $true }, 'Rule')
} else {
    $rows = @($rows | Sort-Object -Property @{ Expression = { $_._FlagCount }; Descending = $true }, 'Rule')
}
$rows = @($rows | Select-Object -Property * -ExcludeProperty _FlagCount, _Risk)

# ---- Output -----------------------------------------------------------------
if ($Json) {
    $payload = $rows | ConvertTo-Json -Depth 10
    if ($payload) { Write-Output $payload }
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} elseif ($Output) {
    $rows | Export-OktaCsv -Path $Output
    Write-Output "Wrote $($rows.Count) rule(s) to $Output"
} elseif ($rows.Count -eq 0) {
    Write-Output 'No group rules found.'
} else {
    $rows | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Output
}
