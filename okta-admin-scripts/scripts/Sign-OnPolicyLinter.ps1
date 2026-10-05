<#
.SYNOPSIS
    Lints Okta sign-on policies for weak authentication and network rules (read-only).

.DESCRIPTION
    READ-ONLY. Enumerates OKTA_SIGN_ON policies and their rules, then flags:
      - PASSWORD_ONLY: rules that grant access (ALLOW) without requiring a
        factor (requireFactor is $false or missing).
      - DEVICE_TRUST_MISSING: rules whose conditions contain no device-trust
        signal (heuristic, case-insensitive text search of the conditions JSON).
      - BROAD_NETWORK: rules that grant access with network connection ANYWHERE.
      - BROAD_ZONE_CIDR: referenced network zones whose gateways use CIDRs with
        a prefix length shorter than -MinZonePrefix (0.0.0.0/0 is always flagged).

    Nothing in the tenant is changed. Findings print as a table by default,
    as JSON with -Json, and can be written to a file with -Output.

.PARAMETER Limit
    Maximum number of sign-on policies to lint. 0 (default) means all policies.

.PARAMETER MinZonePrefix
    Gateway CIDRs with a prefix length shorter than this are flagged.
    Default 16.

.PARAMETER Json
    Emit findings as JSON instead of a table.

.PARAMETER Output
    Write the report to the given file path. The report is JSON when -Json is
    used, otherwise table text.

.EXAMPLE
    pwsh ./Sign-OnPolicyLinter.ps1
    Lints all sign-on policies and prints the findings table.

.EXAMPLE
    pwsh ./Sign-OnPolicyLinter.ps1 -Limit 5 -Json -Output findings.json
    Lints up to 5 policies and writes the findings as JSON to findings.json.

.EXAMPLE
    pwsh ./Sign-OnPolicyLinter.ps1 -MinZonePrefix 24 -Output linter.txt
    Flags zone gateways broader than /24 and writes the table to linter.txt.
#>

param(
    [int]$Limit = 0,
    [int]$MinZonePrefix = 16,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

$findings = @()

$policies = @(Get-OktaPolicies -Client $client -Type 'OKTA_SIGN_ON')
if ($Limit -gt 0 -and $policies.Count -gt $Limit) { $policies = $policies[0..($Limit - 1)] }

$zones = @(Get-OktaZones -Client $client)
$zoneById = @{}
foreach ($z in $zones) { $zoneById[$z.id] = $z }

foreach ($policy in $policies) {
    $rules = @(Get-OktaPolicyRules -Client $client -PolicyId $policy.id)
    foreach ($rule in $rules) {
        $access = $rule.actions.signon.access
        $grantsAccess = ($access -eq 'ALLOW')
        $requireFactor = $rule.actions.signon.requireFactor

        # (a) Password-only auth: explicit ALLOW rule without requireFactor = $true.
        if ($grantsAccess -and ($requireFactor -ne $true)) {
            $findings += [pscustomobject]@{
                Policy   = $policy.name
                Rule     = $rule.name
                Check    = 'PASSWORD_ONLY'
                Severity = 'High'
                Detail   = "Rule grants access without requiring a factor (requireFactor=$requireFactor)."
            }
        }

        # (b) Device-trust heuristic: case-insensitive 'device' search of conditions.
        $condJson = ''
        if ($null -ne $rule.conditions) {
            $condJson = ($rule.conditions | ConvertTo-Json -Depth 10 -Compress)
        }
        if (($condJson -notmatch 'device') -and ($access -ne 'DENY')) {
            $findings += [pscustomobject]@{
                Policy   = $policy.name
                Rule     = $rule.name
                Check    = 'DEVICE_TRUST_MISSING'
                Severity = 'Medium'
                Detail   = 'No device-trust signal found in rule conditions (heuristic text search).'
            }
        }

        # (c) Over-broad network scope.
        $network = $rule.conditions.network
        if ($null -ne $network) {
            if ($grantsAccess -and ($network.connection -eq 'ANYWHERE')) {
                $findings += [pscustomobject]@{
                    Policy   = $policy.name
                    Rule     = $rule.name
                    Check    = 'BROAD_NETWORK'
                    Severity = 'High'
                    Detail   = 'Network connection is ANYWHERE on a rule that grants access.'
                }
            }
            foreach ($zoneId in @($network.include)) {
                if (-not $zoneId) { continue }
                $zone = $zoneById[$zoneId]
                if ($null -eq $zone) { continue }
                foreach ($gw in @($zone.gateways)) {
                    if (-not $gw.value) { continue }
                    $m = [regex]::Match([string]$gw.value, '^(.+)/(\d+)$')
                    if (-not $m.Success) { continue }
                    $prefix = [int]$m.Groups[2].Value
                    if ($prefix -lt $MinZonePrefix) {
                        $sev = 'Medium'
                        if ($prefix -eq 0) { $sev = 'High' }
                        $findings += [pscustomobject]@{
                            Policy   = $policy.name
                            Rule     = $rule.name
                            Check    = 'BROAD_ZONE_CIDR'
                            Severity = $sev
                            Detail   = "Zone '$($zone.name)' gateway $($gw.value) uses prefix /$prefix (narrower than /$MinZonePrefix expected)."
                        }
                    }
                }
            }
        }
    }
}

if ($Json) {
    $payload = $findings | ConvertTo-Json -Depth 10
    if ($payload) { Write-Output $payload }
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} else {
    $findings | Format-Table -AutoSize
    if ($Output) { ($findings | Format-Table -AutoSize | Out-String) | Out-File -FilePath $Output -Encoding utf8 }
}
