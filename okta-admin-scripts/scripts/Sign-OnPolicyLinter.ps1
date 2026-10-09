#Requires -Version 7.0
<#
.SYNOPSIS
    Lints Okta sign-on and app sign-in policy rules for weak settings (read-only).

.DESCRIPTION
    Same checks as sign_on_policy_linter.py, using fields that exist in the
    policy rule schemas:

      NoMfa (OKTA_SIGN_ON rules): access ALLOW with requireFactor false.
        High on Classic orgs (password-only sign-in). Info on Identity
        Engine, where OKTA_SIGN_ON is the global session policy and MFA is
        normally enforced per app in ACCESS_POLICY rules.

      OneFactor (ACCESS_POLICY rules): appSignOn access ALLOW with
        verificationMethod.factorMode 1FA. Medium. Password-recovery-only
        rules are skipped.

      NetworkAnywhere / WideZone: a rule allowing access from ANYWHERE (Low,
        Okta's default), or including a zone with a CIDR wider than
        -MinZonePrefix (Medium; High for /0).

    The engine is detected by whether any ACCESS_POLICY policies exist.

.PARAMETER MinZonePrefix
    Flag zone CIDRs wider than this prefix. Default 16.

.PARAMETER Json
    Print JSON instead of a table.

.PARAMETER Output
    Also write findings to this file (JSON with -Json, otherwise CSV).

.EXAMPLE
    ./Sign-OnPolicyLinter.ps1 -MinZonePrefix 24 -Output ./findings.csv
#>
[CmdletBinding()]
param(
    [int]$MinZonePrefix = 16,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'
$client = New-OktaClient

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($Policy, $Rule, [string]$Check, [string]$Severity, [string]$Detail)
    $script:findings.Add([pscustomobject]@{
        Severity = $Severity; Policy = [string]$Policy.name; PolicyType = [string]$Policy.type
        Rule = [string]$Rule.name; Check = $Check; Detail = $Detail
    })
}

$zoneById = @{}
foreach ($z in Get-OktaZones -Client $client) { $zoneById[[string]$z.id] = $z }

$accessPolicies = @()
try { $accessPolicies = @(Get-OktaPolicies -Client $client -Type 'ACCESS_POLICY') } catch { $accessPolicies = @() }
$oie = $accessPolicies.Count -gt 0
$policies = @(Get-OktaPolicies -Client $client -Type 'OKTA_SIGN_ON') + $accessPolicies

foreach ($policy in $policies) {
    foreach ($rule in Get-OktaPolicyRules -Client $client -PolicyId $policy.id) {
        if ($rule.status -eq 'INACTIVE') { continue }
        if ($policy.type -eq 'OKTA_SIGN_ON') {
            $signon = $rule.actions.signon
            $access = [string]$signon.access
            if ($access -eq 'ALLOW' -and $signon.requireFactor -eq $false) {
                if ($oie) { Add-Finding $policy $rule 'NoMfa' 'Info' 'Global session rule does not require MFA; make sure app sign-in policies do.' }
                else { Add-Finding $policy $rule 'NoMfa' 'High' 'Rule allows sign-in with a password only.' }
            }
        } else {
            $app = $rule.actions.appSignOn
            $access = [string]$app.access
            $cond = ([string]$rule.conditions.elCondition.condition) -replace '\s', ''
            if ($access -eq 'ALLOW' -and $app.verificationMethod.factorMode -eq '1FA' -and $cond -notmatch "accessRequest\.operation=='recover'") {
                Add-Finding $policy $rule 'OneFactor' 'Medium' 'App sign-in rule allows access with one factor.'
            }
        }
        if ($access -ne 'ALLOW') { continue }
        $network = $rule.conditions.network
        if ($network.connection -eq 'ANYWHERE') { Add-Finding $policy $rule 'NetworkAnywhere' 'Low' 'Rule applies from any network.' }
        foreach ($zoneId in @($network.include)) {
            $zone = if ($zoneId) { $zoneById[[string]$zoneId] } else { $null }
            if (-not $zone) { continue }
            foreach ($gw in @($zone.gateways)) {
                if ($gw.type -ne 'CIDR' -or [string]$gw.value -notmatch '/(\d+)$') { continue }
                $prefix = [int]$Matches[1]
                if ($prefix -lt $MinZonePrefix) {
                    $sev = if ($prefix -eq 0) { 'High' } else { 'Medium' }
                    Add-Finding $policy $rule 'WideZone' $sev "Zone '$($zone.name)' includes $($gw.value)."
                }
            }
        }
    }
}

$order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
$sorted = @($findings | Sort-Object { $order[$_.Severity] }, Policy)
if ($Json) {
    $text = ConvertTo-Json -InputObject $sorted -Depth 5
    Write-Output $text
    if ($Output) { $text | Out-File -LiteralPath $Output -Encoding utf8 }
} else {
    $sorted | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Output
    $engine = if ($oie) { 'Identity Engine' } else { 'Classic' }
    Write-Output "$($engine): $($policies.Count) policies, $($sorted.Count) findings"
    if ($Output) { $sorted | Export-OktaCsv -Path $Output }
}
