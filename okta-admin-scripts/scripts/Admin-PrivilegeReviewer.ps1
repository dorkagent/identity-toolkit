#Requires -Version 7.0
<#
.SYNOPSIS
    Lists every Okta admin-role holder and flags grants that look unused (read-only).

.DESCRIPTION
    Holders come from GET /api/v1/iam/assignees/users (direct and group
    assignments). For each one, GET /api/v1/users/{id}/roles returns every
    role with assignmentType USER (direct) or GROUP. All role types are
    shown, including CUSTOM roles (by label), REPORT_ADMIN and
    WORKFLOWS_ADMIN.

    STALE means the oldest role assignment ("created") is older than
    -StaleDays and the System Log has no events with that user as actor in
    the window. Okta keeps 90 days of System Log, so the activity check never
    looks further back than that.

    MFA counts ACTIVE factors and lists phishing-resistant ones (webauthn,
    u2f, signed_nonce = FastPass). On Identity Engine the factors API answers
    in the calling admin's policy context, so treat it as a hint.

.PARAMETER StaleDays
    Default 90.

.PARAMETER Json
    Print JSON instead of a table.

.PARAMETER Output
    Also write the report to this file (JSON with -Json, otherwise CSV).

.EXAMPLE
    ./Admin-PrivilegeReviewer.ps1 -Output ./admins.csv
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 90,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'
$client = New-OktaClient

$strongTypes = @('webauthn', 'u2f', 'signed_nonce')
$now = [datetime]::UtcNow
$windowDays = [Math]::Min($StaleDays, 90)
$since = $now.AddDays(-$windowDays).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$until = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

function Get-RoleName {
    param($Role)
    if ($Role.type -eq 'CUSTOM') { return "CUSTOM:$($Role.label)" }
    return [string]$Role.type
}

$rows = [System.Collections.Generic.List[object]]::new()
foreach ($uid in Get-OktaRoleAssigneeUserIds -Client $client) {
    $user = Invoke-OktaRequest -Client $client -Method GET -Path "/api/v1/users/$uid"
    $roles = @(Get-OktaUserRoles -Client $client -UserId $uid)
    $created = @($roles | ForEach-Object { ConvertTo-OktaUtcDate $_.created } | Where-Object { $_ } | Sort-Object)
    $oldest = if ($created.Count) { $created[0] } else { $null }

    $last = $null
    foreach ($e in Get-OktaLogs -Client $client -Filter "actor.id eq `"$uid`"" -Since $since -Until $until) {
        $t = ConvertTo-OktaUtcDate $e.published
        if (-not $last -or $t -gt $last) { $last = $t }
    }

    $active = @(Get-OktaFactors -Client $client -UserId $uid | Where-Object { $_.status -eq 'ACTIVE' })
    $strong = @($active | Where-Object { $strongTypes -contains $_.factorType } | ForEach-Object factorType | Sort-Object -Unique)
    $mfa = if ($active.Count -eq 0) { 'none' } elseif ($strong.Count) { "$($active.Count) active ($($strong -join ', '))" } else { "$($active.Count) active, none phishing-resistant" }

    $rows.Add([pscustomobject]@{
        Login        = [string]$user.profile.login
        Status       = [string]$user.status
        DirectRoles  = (@($roles | Where-Object { $_.assignmentType -eq 'USER' } | ForEach-Object { Get-RoleName $_ } | Sort-Object) -join ', ')
        GroupRoles   = (@($roles | Where-Object { $_.assignmentType -eq 'GROUP' } | ForEach-Object { Get-RoleName $_ } | Sort-Object) -join ', ')
        OldestGrant  = if ($oldest) { $oldest.ToString('yyyy-MM-dd') } else { '' }
        LastActivity = if ($last) { $last.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'none' }
        MFA          = $mfa
        Stale        = [bool]($oldest -and $oldest -lt $now.AddDays(-$StaleDays) -and -not $last)
    })
}

$report = @($rows | Sort-Object @{ Expression = 'Stale'; Descending = $true }, Login)
if ($Json) {
    $text = ConvertTo-Json -InputObject $report -Depth 5
    Write-Output $text
    if ($Output) { $text | Out-File -LiteralPath $Output -Encoding utf8 }
} else {
    $report | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
    Write-Output ("{0} role holders, {1} stale (activity window {2} days)" -f $report.Count, @($report | Where-Object Stale).Count, $windowDays)
    if ($Output) { $report | Export-OktaCsv -Path $Output }
}
