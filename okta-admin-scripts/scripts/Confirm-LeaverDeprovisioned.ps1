<#
.SYNOPSIS
    Verifies a terminated user's access is fully revoked in Okta.

.DESCRIPTION
    Given a user's login, runs seven read-only checks: account disabled,
    sessions revoked, app assignments removed, admin roles removed, MFA
    factors removed, group memberships cleared, and API tokens revoked.
    Each check reports PASS/FAIL/WARN with evidence (IDs, timestamps), so
    the report answers an auditor's "did it actually stick?" without
    hand-built spreadsheets.

    WARN means the check could not be evaluated (an API call failed) --
    it is neither a pass nor proof of a problem. The evidence always says
    what went wrong.

    Evidence notes worth knowing:
      - SessionsRevoked queries the System Log for session-start events after
        the account's statusChanged timestamp. Okta's /users/{id}/sessions
        endpoint is DELETE-only (there is no read API listing live sessions),
        so the log is the evidence: a disabled account that still starts
        sessions FAILs this check.
      - AppAssignmentsRemoved uses the user's appLinks -- the effective
        list of apps they can still reach, whatever granted the access.
      - MfaFactorsRemoved FAILs only on ACTIVE factors. Okta
        lifecycle-deactivates factors on deprovision, so INACTIVE factors
        on a DEPROVISIONED user are expected, not a finding.
      - GroupMembershipsCleared ignores the Everyone group. Okta retains
        deprovisioned users in Everyone; that membership is expected.
      - ApiTokensRevoked lists tenant tokens and matches on owner. The
        endpoint (GET /api/v1/api-tokens) requires a SUPER-ADMIN API token --
        without one the check reports WARN instead of a false PASS.

    READ-ONLY: every HTTP call is a GET. The script never changes anything
    in the tenant.

    Exit code is 0 when the verdict is COMPLETE, 1 when it is INCOMPLETE
    or the user cannot be found.

.PARAMETER Login
    The user's Okta login (username/email). Required.

.PARAMETER Json
    Emit the report as JSON instead of a table.

.PARAMETER Output
    Write the report to the given file path. CSV by default, JSON with -Json.

.PARAMETER Limit
    Cap the evidence items shown per check. 0 (default) = show all.

.EXAMPLE
    pwsh ./Confirm-LeaverDeprovisioned.ps1 -Login jdoe@example.com
    Runs the seven checks and prints a PASS/FAIL/WARN table. Exits 0 only
    when every check passes.

.EXAMPLE
    pwsh ./Confirm-LeaverDeprovisioned.ps1 -Login jdoe@example.com -Json -Output leaver.json
    Writes the full evidence report as JSON to leaver.json.

.EXAMPLE
    pwsh ./Confirm-LeaverDeprovisioned.ps1 -Login jdoe@example.com -Limit 5 -Output leaver.csv
    Shows at most 5 evidence items per check and writes the CSV report.
#>

param(
    [Parameter(Mandatory)][string]$Login,
    [switch]$Json,
    [string]$Output,
    [int]$Limit = 0
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

function Format-EvidenceItems {
    <#
    .SYNOPSIS
        Join evidence strings, capping the list when -Limit is set.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Items = @(),
        [int]$Limit = 0,
        [string]$EmptyText = 'none'
    )
    $list = @($Items | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { return $EmptyText }
    $shown = $list
    $overflow = 0
    if ($Limit -gt 0 -and $list.Count -gt $Limit) {
        $shown = @($list | Select-Object -First $Limit)
        $overflow = $list.Count - $Limit
    }
    $text = ($shown -join '; ')
    if ($overflow -gt 0) { $text += " (+$overflow more)" }
    return $text
}

function New-CheckResult {
    <#
    .SYNOPSIS
        Build one PASS/FAIL/WARN check row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'WARN')][string]$Result,
        [string]$Evidence = ''
    )
    return [pscustomobject]@{
        Check    = $Name
        Result   = $Result
        Evidence = $Evidence
    }
}

$user = Get-OktaUserByLogin -Client $client -Login $Login
if ($null -eq $user) { throw "No user found with login '$Login'." }
$userId = $user.id

$checks = @()

# 1. Account disabled.
$statusOk = $user.status -in @('DEPROVISIONED', 'SUSPENDED')
$lastLogin = $user.lastLogin
if ($null -eq $lastLogin) { $lastLogin = '(never)' }
$check1Result = if ($statusOk) { 'PASS' } else { 'FAIL' }
$checks += New-CheckResult -Name 'AccountDisabled' -Result $check1Result -Evidence `
    "status=$($user.status); statusChanged=$($user.statusChanged); lastLogin=$lastLogin"

# 2. Sessions revoked. Okta's /users/{id}/sessions endpoint is DELETE-only --
#    there is no GET to list live sessions -- so the System Log is the honest
#    evidence: session-start events after the account was disabled mean
#    sessions were NOT effectively revoked.
$postDisableLogins = 0
$logFailed = $false
$logNote = ''
try {
    if ($user.statusChanged) {
        $filter = "eventType eq `"user.session.start`" and target.id eq `"$userId`""
        $events = @(Get-OktaLogs -Client $client -Filter $filter -Since $user.statusChanged | Select-Object -First 6)
        $postDisableLogins = $events.Count
        if ($events.Count -eq 0) {
            $logNote = '0 session-start events in the System Log since disabled'
        } else {
            $latest = $events[-1].published
            $more = if ($events.Count -ge 6) { '+' } else { '' }
            $logNote = "$($events.Count)$more session-start event(s) since disabled (latest $latest)"
        }
    } else {
        $logNote = 'statusChanged missing; System Log cross-check skipped'
        $logFailed = $true
    }
} catch {
    $logNote = "System Log cross-check unavailable: $($_.Exception.Message)"
    $logFailed = $true
}
$check2Result = if (-not $statusOk) { 'FAIL' }
               elseif ($logFailed) { 'WARN' }
               elseif ($postDisableLogins -eq 0) { 'PASS' }
               else { 'FAIL' }
$checks += New-CheckResult -Name 'SessionsRevoked' -Result $check2Result -Evidence $logNote

# 3. App assignments removed (appLinks = the effective apps the user can
#    still reach, however the access was granted).
try {
    $appLinks = @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/users/$userId/appLinks")
    $items = @($appLinks | ForEach-Object {
        "app '$($_.label)' [$($_.appName)] id=$($_.id)"
    })
    $checks += New-CheckResult -Name 'AppAssignmentsRemoved' `
        -Result $(if ($appLinks.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence $(Format-EvidenceItems -Items $items -Limit $Limit -EmptyText '0 reachable apps')
} catch {
    $checks += New-CheckResult -Name 'AppAssignmentsRemoved' -Result 'WARN' `
        -Evidence "could not list app links: $($_.Exception.Message)"
}

# 4. Admin roles removed
try {
    $roles = @(Get-OktaUserRoles -Client $client -UserId $userId)
    $items = @($roles | ForEach-Object {
        "role $($_.label) [$($_.type)] id=$($_.id)"
    })
    $checks += New-CheckResult -Name 'AdminRolesRemoved' `
        -Result $(if ($roles.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence $(Format-EvidenceItems -Items $items -Limit $Limit -EmptyText 'no admin roles')
} catch {
    $checks += New-CheckResult -Name 'AdminRolesRemoved' -Result 'WARN' `
        -Evidence "could not list roles: $($_.Exception.Message)"
}

# 5. MFA factors removed. Okta lifecycle-deactivates factors on deprovision,
#    so only ACTIVE factors are a finding; INACTIVE leftovers are expected.
try {
    $factors = @(Get-OktaFactors -Client $client -UserId $userId)
    $active = @($factors | Where-Object { $_.status -eq 'ACTIVE' })
    $items = @($factors | ForEach-Object {
        "factor $($_.factorType):$($_.provider) [$($_.id)] status=$($_.status)"
    })
    $evidence = Format-EvidenceItems -Items $items -Limit $Limit -EmptyText 'no enrolled factors'
    if ($factors.Count -gt 0 -and $active.Count -eq 0) {
        $evidence += ' (all factors non-ACTIVE; Okta deactivates factors on deprovision -- expected)'
    }
    $checks += New-CheckResult -Name 'MfaFactorsRemoved' `
        -Result $(if ($active.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence $evidence
} catch {
    $checks += New-CheckResult -Name 'MfaFactorsRemoved' -Result 'WARN' `
        -Evidence "could not list factors: $($_.Exception.Message)"
}

# 6. Group memberships cleared. Okta retains deprovisioned users in the
#    Everyone group, so Everyone alone is a PASS, not a finding.
try {
    $groups = @(Invoke-OktaPagedGet -Client $client -Path "/api/v1/users/$userId/groups")
    $nonEveryone = @($groups | Where-Object { $_.profile.name -ne 'Everyone' })
    $items = @($groups | ForEach-Object {
        "group '$($_.profile.name)' [$($_.type)] id=$($_.id)"
    })
    $evidence = Format-EvidenceItems -Items $items -Limit $Limit -EmptyText 'no group memberships'
    if ($nonEveryone.Count -eq 0 -and $groups.Count -gt 0) {
        $evidence += ' (Everyone membership is retained by Okta on deprovisioned users -- expected)'
    }
    $checks += New-CheckResult -Name 'GroupMembershipsCleared' `
        -Result $(if ($nonEveryone.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence $evidence
} catch {
    $checks += New-CheckResult -Name 'GroupMembershipsCleared' -Result 'WARN' `
        -Evidence "could not list groups: $($_.Exception.Message)"
}

# 7. API tokens revoked. Tokens carry their owner's userId, so the tenant
#    token list is filtered down to this user.
try {
    $tokens = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/api-tokens' |
        Where-Object { $_.userId -eq $userId })
    $items = @($tokens | ForEach-Object {
        "token '$($_.name)' [$($_.id)] created=$($_.created) lastUsed=$($_.lastUpdated) expires=$($_.expiresAt)"
    })
    $checks += New-CheckResult -Name 'ApiTokensRevoked' `
        -Result $(if ($tokens.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
        -Evidence $(Format-EvidenceItems -Items $items -Limit $Limit -EmptyText 'no API tokens owned')
} catch {
    $detail = $_.Exception.Message
    if ($detail -match 'HTTP 40[13]') {
        $detail = 'GET /api/v1/api-tokens requires a SUPER-ADMIN API token; ordinary read-only tokens are rejected. ' + $detail
    }
    $checks += New-CheckResult -Name 'ApiTokensRevoked' -Result 'WARN' `
        -Evidence "could not verify tokens: $detail"
}

$failCount = @($checks | Where-Object { $_.Result -eq 'FAIL' }).Count
$warnCount = @($checks | Where-Object { $_.Result -eq 'WARN' }).Count
$verdict = if ($failCount -eq 0 -and $warnCount -eq 0) { 'COMPLETE' } else { 'INCOMPLETE' }

$report = [pscustomobject]@{
    Tenant     = $client.BaseUrl
    Login      = $user.profile.login
    UserId     = $userId
    Name       = (@($user.profile.firstName, $user.profile.lastName) -join ' ').Trim()
    UserStatus = $user.status
    CheckedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Verdict    = $verdict
    Passed     = $checks.Count - $failCount - $warnCount
    Failed     = $failCount
    Warned     = $warnCount
    Checks     = $checks
}

if ($Json) {
    $payload = $report | ConvertTo-Json -Depth 10
    if ($payload) { Write-Output $payload }
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} else {
    Write-Output "Leaver verification: $($report.Login) [$($report.UserId)] status=$($report.UserStatus) -- verdict: $($report.Verdict) ($($report.Passed)/$($checks.Count) checks passed)"
    $checks | Format-Table -AutoSize | Out-String -Width 200 | Write-Output
    if ($Output) { $checks | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8 }
}

if ($verdict -eq 'COMPLETE') { exit 0 } else { exit 1 }
