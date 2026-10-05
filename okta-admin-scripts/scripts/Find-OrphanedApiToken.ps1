<#
.SYNOPSIS
    Finds orphaned and privileged Okta API tokens (owner-correlation audit).

.DESCRIPTION
    Okta's Tokens page already shows each token's age, expiry, and last use --
    but it won't tell you whether the human behind the token is still
    employed, or what admin privileges that human holds. This script closes
    that gap: it lists every API token, resolves the token's owner, and
    reports the owner's lifecycle state (active/suspended/deprovisioned), the
    owner's admin roles, and last use.

    Flagged findings:
      OwnerGone          -- the owner's user record is gone (lookup 404s).
      OwnerDeprovisioned -- the owner is in DEPROVISIONED status.
      OwnerSuspended     -- the owner is in SUSPENDED status.
      PrivilegedOwner    -- the owner holds at least one admin role
                            (role types are listed).

    GET /api/v1/api-tokens requires a SUPER-ADMIN API token; ordinary
    read-only tokens are rejected with 401/403 and the script says so.

    READ-ONLY: every HTTP call is a GET. The script never changes anything
    in the tenant. Findings are revocation candidates, not revocations.

.PARAMETER OutputDir
    Directory for the timestamped evidence pack. Defaults to
    "token-report-yyyyMMddHHmmss". Created if missing.

.PARAMETER Json
    Also dump the token rows as JSON to the console.

.PARAMETER Limit
    Process at most this many tokens (0 = all).

.EXAMPLE
    pwsh ./Find-OrphanedApiToken.ps1
    Builds token-report-<timestamp>/ with tokens.csv and SUMMARY.md and
    prints the flagged tokens to the console.

.EXAMPLE
    pwsh ./Find-OrphanedApiToken.ps1 -OutputDir ./audit-tokens -Json
    Writes the pack to ./audit-tokens and dumps the rows as JSON.
#>

param(
    [string]$OutputDir,
    [switch]$Json,
    [int]$Limit = 0
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

function Get-OktaUserOrNull {
    <#
    .SYNOPSIS
        Fetch a user by id; return $null when the user is gone (HTTP 404).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [Parameter(Mandatory)][string]$UserId
    )
    try {
        return Invoke-OktaRequest -Client $Client -Method GET -Path "/api/v1/users/$UserId"
    } catch {
        if ("$($_.Exception.Message)" -match 'error 404') { return $null }
        throw
    }
}

# Token listing needs a super-admin token -- say so plainly on 401/403.
try {
    $tokens = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/api-tokens')
} catch {
    if ("$($_.Exception.Message)" -match 'HTTP 40[13]') {
        throw "GET /api/v1/api-tokens was rejected ($($_.Exception.Message)). This endpoint requires a SUPER-ADMIN API token -- ordinary read-only tokens cannot list API tokens."
    }
    throw
}
if ($Limit -gt 0 -and $tokens.Count -gt $Limit) { $tokens = @($tokens | Select-Object -First $Limit) }

$rows = @()
foreach ($token in $tokens) {
    $ownerId = $token.userId
    $owner = $null
    $ownerLogin = $null
    $ownerName = $null
    $ownerStatus = 'UNKNOWN'
    $ownerGone = $false
    if (-not $ownerId) {
        $ownerGone = $true
    } else {
        $owner = Get-OktaUserOrNull -Client $client -UserId $ownerId
        if ($null -eq $owner) {
            $ownerGone = $true
        } else {
            $ownerStatus = $owner.status
            $ownerLogin = $owner.profile.login
            $ownerName = (@($owner.profile.firstName, $owner.profile.lastName) -join ' ').Trim()
        }
    }

    $roleTypes = @()
    if (-not $ownerGone -and $ownerId) {
        $roleTypes = @(Get-OktaUserRoles -Client $client -UserId $ownerId | ForEach-Object { $_.type })
    }

    $flags = @()
    if ($ownerGone) { $flags += 'OwnerGone' }
    elseif ($ownerStatus -eq 'DEPROVISIONED') { $flags += 'OwnerDeprovisioned' }
    elseif ($ownerStatus -eq 'SUSPENDED') { $flags += 'OwnerSuspended' }
    if ($roleTypes.Count -gt 0) { $flags += 'PrivilegedOwner' }

    $rows += [pscustomobject]@{
        TokenId     = $token.id
        TokenName   = $token.name
        OwnerLogin  = $ownerLogin
        OwnerName   = $ownerName
        OwnerId     = $ownerId
        OwnerStatus = $ownerStatus
        OwnerRoles  = ($roleTypes -join '; ')
        Created     = $token.created
        ExpiresAt   = $token.expiresAt
        LastUsed    = $token.lastUpdated
        Flags       = ($flags -join '; ')
    }
}

$flagged = @($rows | Where-Object { $_.Flags })
$flagCounts = @{}
foreach ($flag in @($flagged | ForEach-Object { $_.Flags -split '; ' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $flagCounts[$flag] = ($flagCounts[$flag] ?? 0) + 1
}

# ---- Evidence pack -------------------------------------------------------
if (-not $OutputDir) {
    $OutputDir = "token-report-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss')
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$csvPath = Join-Path $OutputDir 'tokens.csv'
$rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$md = @()
$md += '# Exhibit: Orphaned and privileged Okta API tokens'
$md += ''
$md += "Tenant: $($client.BaseUrl)"
$md += "Generated: $stamp (UTC)"
$md += "Tokens examined: $($rows.Count)"
$md += "Tokens flagged: $($flagged.Count)"
$md += ''
$md += '> Okta''s Tokens page reports age, expiry, and last use -- this exhibit'
$md += '> answers the two questions it cannot: is the token''s owner still'
$md += '> employed, and what admin privileges does the owner hold? Every API'
$md += '> call made to produce this report was a read-only GET.'
$md += ''
$md += '## Finding counts'
$md += ''
foreach ($flag in @('OwnerGone', 'OwnerDeprovisioned', 'OwnerSuspended', 'PrivilegedOwner')) {
    $count = 0
    if ($flagCounts.ContainsKey($flag)) { $count = $flagCounts[$flag] }
    $md += "- $flag : $count"
}
$md += ''
$md += '## Flagged tokens'
$md += ''
if ($flagged.Count -eq 0) {
    $md += 'No flagged tokens. Every API token is owned by an active,'
    $md += 'non-privileged user -- or no tokens exist in the tenant.'
} else {
    foreach ($row in $flagged) {
        $md += "### Token '$($row.TokenName)' [$($row.TokenId)]"
        $md += ''
        $md += "- Owner: $(if ($row.OwnerLogin) { $row.OwnerLogin } else { '(unknown -- owner record unavailable)' }) (status: $($row.OwnerStatus))"
        $md += "- Owner admin roles: $(if ($row.OwnerRoles) { $row.OwnerRoles } else { 'none' })"
        $md += "- Last used: $(if ($row.LastUsed) { $row.LastUsed } else { 'never recorded' })"
        $md += "- Expires: $(if ($row.ExpiresAt) { $row.ExpiresAt } else { 'no expiry set' })"
        foreach ($flag in ($row.Flags -split '; ')) {
            switch ($flag.Trim()) {
                'OwnerGone'          { $md += "- FINDING: the owner's user record is gone (or no owner is recorded on the token). This token has no living owner -- revoke it after confirming no service depends on it." }
                'OwnerDeprovisioned' { $md += "- FINDING: the owner is DEPROVISIONED (no longer employed / offboarded). A token can outlive its owner's employment -- verify and revoke." }
                'OwnerSuspended'     { $md += "- FINDING: the owner is SUSPENDED. A live token on a suspended account is a backdoor -- verify and revoke." }
                'PrivilegedOwner'    { $md += "- NOTE: the owner holds admin role(s) ($($row.OwnerRoles)). Confirm this level of standing access is still warranted." }
            }
        }
        $md += ''
    }
}
$md += '## What this exhibit does not do'
$md += ''
$md += '- Nothing here was revoked, disabled, or changed -- the report is'
$md += '  strictly read-only. Revoke candidates in Okta Admin Console'
$md += '  (Settings > API > Tokens) after confirming no service depends'
$md += '  on the token.'
$md += '- Token age, expiry, and last use are already shown on Okta''s native'
$md += '  Tokens page and are repeated here only for context. "Last used" is'
$md += '  sourced from the token''s lastUpdated timestamp -- the only usage'
$md += '  signal the API exposes on the token object.'
$summaryPath = Join-Path $OutputDir 'SUMMARY.md'
$md -join [Environment]::NewLine | Out-File -FilePath $summaryPath -Encoding utf8

# ---- Console output ------------------------------------------------------
Write-Output "Token audit complete: $($rows.Count) tokens examined, $($flagged.Count) flagged. Evidence pack: $OutputDir (tokens.csv, SUMMARY.md)"
if ($Json) {
    $payload = $rows | ConvertTo-Json -Depth 6
    if ($payload) { Write-Output $payload }
} else {
    if ($flagged.Count -gt 0) {
        Write-Output ''
        Write-Output 'Flagged tokens:'
        $flagged |
            Select-Object TokenName, OwnerLogin, OwnerStatus, OwnerRoles, LastUsed, Flags |
            Format-Table -AutoSize |
            Out-String -Width 200 |
            Write-Output
    } else {
        Write-Output 'No flagged tokens.'
    }
}
