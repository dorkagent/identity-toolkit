<#
.SYNOPSIS
    Lints Okta Identity Engine authentication posture in one read-only run.

.DESCRIPTION
    READ-ONLY. Checks the four OIE posture areas in a single pass:
      (a) Authentication policies (ACCESS_POLICY) and their rules: rules that
          grant access with password only (factorMode 1FA), and rules with no
          phishing-resistant requirement (WebAuthn/FIDO2). Policies whose name
          contains "admin" are treated as admin-scoped (heuristic) and their
          missing phishing resistance is escalated.
      (b) Authenticator catalog (/api/v1/authenticators): weak methods still
          ACTIVE (SMS/voice/phone, security questions) and the absence of any
          active WebAuthn/FIDO2 authenticator; plus MFA enrollment policies
          whose required methods (amr) are password-only or lack a
          phishing-resistant option.
      (c) Password policies: minimum length below -MinPasswordLength and empty
          character-complexity requirements.
      (d) Network zones: ACTIVE custom zones with 0.0.0.0/0 or very broad CIDR
          gateways (scored worse when an auth-policy rule references the
          zone), and INACTIVE zones still referenced by auth-policy rules
          (their network conditions can never match).

    This is the OIE counterpart to Sign-OnPolicyLinter.ps1, which covers
    classic OKTA_SIGN_ON policies only. Nothing here reads or flags classic
    sign-on policies.

    Findings print as a table by default, sorted scariest-first, as JSON with
    -Json, and can be written to a file with -Output (.csv writes CSV).

.PARAMETER Limit
    Maximum number of authentication policies to lint. 0 (default) means all.
    Enrollment, password, authenticator and zone checks always cover the whole
    tenant.

.PARAMETER MinZonePrefix
    Zone gateway CIDRs with a prefix length shorter than this are flagged.
    Default 16.

.PARAMETER MinPasswordLength
    Password policies with a minimum length below this are flagged.
    Default 12.

.PARAMETER Json
    Emit findings as JSON instead of a table.

.PARAMETER Output
    Write the report to the given file path. JSON when -Json is used;
    CSV when the path ends in .csv; otherwise table text.

.EXAMPLE
    pwsh ./Test-OiePosture.ps1
    Lints the whole OIE posture and prints the findings table, scariest first.

.EXAMPLE
    pwsh ./Test-OiePosture.ps1 -Limit 3 -Json -Output oie-posture.json
    Lints up to 3 authentication policies and writes the findings as JSON.

.EXAMPLE
    pwsh ./Test-OiePosture.ps1 -Output oie-posture.csv
    Writes all findings as CSV to oie-posture.csv.
#>

param(
    [int]$Limit = 0,
    [int]$MinZonePrefix = 16,
    [int]$MinPasswordLength = 12,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

$sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$findings = @()

function Add-Finding {
    <#
    .SYNOPSIS
        Build one posture finding row.
    #>
    param(
        [string]$Check,
        [string]$Severity,
        [string]$Target,
        [string]$Risk,
        [string]$Evidence
    )
    return [pscustomobject]@{
        Check    = $Check
        Severity = $Severity
        Target   = $Target
        Risk     = $Risk
        Evidence = $Evidence
    }
}

# --- (a) Authentication policies + rules ------------------------------------
$authPolicies = @(Get-OktaPolicies -Client $client -Type 'ACCESS_POLICY')
if ($Limit -gt 0 -and $authPolicies.Count -gt $Limit) {
    $authPolicies = @($authPolicies[0..($Limit - 1)])
}

$referencedZoneIds = @()

foreach ($policy in $authPolicies) {
    $policyName = [string]$policy.name
    # Heuristic: the Okta Admin Console auth policy carries "admin" in its name.
    $adminScope = $policyName -match 'admin'
    $rules = @(Get-OktaPolicyRules -Client $client -PolicyId $policy.id)
    foreach ($rule in $rules) {
        $ruleName = [string]$rule.name
        $target = "Auth policy '$policyName' / rule '$ruleName'"

        # Collect zone references even from DENY rules; an INACTIVE zone is a
        # problem wherever a rule points at it.
        $zoneIds = @()
        if ($null -ne $rule.conditions -and $null -ne $rule.conditions.network -and
            $null -ne $rule.conditions.network.include) {
            $zoneIds = @($rule.conditions.network.include)
        }
        foreach ($zid in $zoneIds) {
            if ($zid) { $referencedZoneIds += [string]$zid }
        }

        $signOn = $rule.actions.appSignOn
        if ($null -eq $signOn -or [string]$signOn.access -ne 'ALLOW') { continue }

        $verify = $signOn.verificationMethod
        $factorMode = ''
        if ($null -ne $verify) { $factorMode = [string]$verify.factorMode }

        # Password-only rule: 1FA means possession of the password alone signs in.
        if ($factorMode -eq '1FA') {
            $findings += Add-Finding -Check 'AUTH_PASSWORD_ONLY' -Severity 'High' `
                -Target $target `
                -Risk 'Anyone who knows the password gets in - no second factor stands in the way of credential stuffing or phishing.' `
                -Evidence "actions.appSignOn.verificationMethod.factorMode = '1FA'."
            continue
        }

        # No phishing-resistant requirement on a 2FA rule.
        $constraints = @()
        if ($null -ne $verify -and $null -ne $verify.constraints) {
            $constraints = @($verify.constraints)
        }
        $phishRequired = $false
        foreach ($c in $constraints) {
            if ($null -ne $c -and $c.possession.phishingResistant -eq 'REQUIRED') {
                $phishRequired = $true
            }
        }
        if (-not $phishRequired) {
            $sev = 'Medium'
            $check = 'AUTH_NO_PHISHING_RESISTANT'
            $risk = 'A phished one-time code or push approval is enough to sign in - only a phishing-resistant factor (WebAuthn/FIDO2) stops that.'
            if ($adminScope) {
                $sev = 'High'
                $check = 'AUTH_NO_PHISHING_ADMIN'
                $risk = 'Admins can sign in without a phishing-resistant factor - a single phished code hands over the whole tenant.'
            }
            $findings += Add-Finding -Check $check -Severity $sev -Target $target `
                -Risk $risk `
                -Evidence "factorMode = '$factorMode' with no constraints[].possession.phishingResistant = 'REQUIRED'."
        }
    }
}

# --- (b) Authenticator catalog ----------------------------------------------
$authenticators = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/authenticators')
$activeAuthenticators = @($authenticators | Where-Object { $null -ne $_ -and $_.status -eq 'ACTIVE' })

$webAuthn = @($activeAuthenticators | Where-Object { $_.key -in @('webauthn', 'fido2') })
if ($webAuthn.Count -eq 0) {
    $findings += Add-Finding -Check 'AUTHENTICATOR_NO_WEBAUTHN' -Severity 'High' `
        -Target 'Authenticator catalog' `
        -Risk 'The tenant offers no phishing-resistant sign-in option at all - every user is one phished code away from account takeover.' `
        -Evidence 'No ACTIVE authenticator with key webauthn or fido2.'
}

$weakKeys = @('phone', 'sms', 'voice', 'call', 'security_question')
foreach ($a in $activeAuthenticators) {
    if ($a.key -in $weakKeys) {
        $findings += Add-Finding -Check 'AUTHENTICATOR_WEAK_METHOD' -Severity 'Medium' `
            -Target "Authenticator '$([string]$a.name)' (key=$([string]$a.key))" `
            -Risk 'SMS and voice codes can be intercepted or SIM-swapped, and security questions are guessable - keeping these available gives attackers the weakest path in.' `
            -Evidence "status=ACTIVE, settings.allowedFor=$([string]$a.settings.allowedFor)."
    }
}

# --- (b2) MFA enrollment policies --------------------------------------------
# Phishing-resistant AMR values: WebAuthn software / hardware keys with user
# verification. (hwk alone is U2F without user verification.)
$phishResistantAmr = @('swk_uv', 'hwk_uv')
$enrollPolicies = @(Get-OktaPolicies -Client $client -Type 'MFA_ENROLL')
foreach ($policy in $enrollPolicies) {
    $policyName = [string]$policy.name
    $rules = @(Get-OktaPolicyRules -Client $client -PolicyId $policy.id)
    foreach ($rule in $rules) {
        $enroll = $rule.actions.enroll
        if ($null -eq $enroll) { continue }
        if ([string]$enroll.self -eq 'DISABLED') { continue }  # enrollment turned off; nothing required to compare
        $amr = @()
        if ($null -ne $enroll.amr) { $amr = @($enroll.amr) }
        if ($amr.Count -eq 0) { continue }  # API did not return required methods; nothing defensible to say

        $target = "Enrollment policy '$policyName' / rule '$([string]$rule.name)'"
        $adminScope = ($policyName -match 'admin') -or ([string]$rule.name -match 'admin')
        $hasPhishResistant = $false
        foreach ($m in $amr) {
            if ($m -in $phishResistantAmr) { $hasPhishResistant = $true }
        }

        if ($amr.Count -eq 1 -and $amr[0] -eq 'pwd') {
            $sev = 'High'
            if ($adminScope) { $sev = 'Critical' }
            $findings += Add-Finding -Check 'ENROLL_PASSWORD_ONLY' -Severity $sev `
                -Target $target `
                -Risk 'Users are only required to enroll a password - nobody is ever forced to set up a second factor.' `
                -Evidence "actions.enroll.amr = ['pwd']."
        } elseif (-not $hasPhishResistant) {
            $sev = 'Medium'
            if ($adminScope) { $sev = 'High' }
            $findings += Add-Finding -Check 'ENROLL_NO_PHISHING_RESISTANT' -Severity $sev `
                -Target $target `
                -Risk 'Users must enroll a second factor, but none of the allowed options resists phishing - a stolen code still wins.' `
                -Evidence "actions.enroll.amr = ['$($amr -join "', '")']; no swk_uv/hwk_uv present."
        }
    }
}

# --- (c) Password policies ----------------------------------------------------
$pwdPolicies = @(Get-OktaPolicies -Client $client -Type 'PASSWORD')
foreach ($policy in $pwdPolicies) {
    $target = "Password policy '$([string]$policy.name)'"
    $complexity = $policy.settings.password.complexity
    if ($null -eq $complexity) {
        $findings += Add-Finding -Check 'PASSWORD_NO_COMPLEXITY' -Severity 'Medium' `
            -Target $target `
            -Risk 'The policy carries no complexity requirements that the API can see - users can pick passwords like "password123456789".' `
            -Evidence 'settings.password.complexity is missing from the API response.'
        continue
    }
    $minLength = [int]$complexity.minLength
    if ($minLength -lt $MinPasswordLength) {
        $findings += Add-Finding -Check 'PASSWORD_SHORT' -Severity 'Medium' `
            -Target $target `
            -Risk "Passwords as short as $minLength characters are allowed - short passwords fall far faster to guessing and cracking." `
            -Evidence "minLength=$minLength (expected at least $MinPasswordLength)."
    }
    $classes = [int]$complexity.minLowerCase + [int]$complexity.minUpperCase +
               [int]$complexity.minNumber + [int]$complexity.minSymbol
    if ($classes -eq 0) {
        $findings += Add-Finding -Check 'PASSWORD_NO_COMPLEXITY' -Severity 'Medium' `
            -Target $target `
            -Risk 'No character variety is required - users can pick passwords like "password123456789".' `
            -Evidence 'minLowerCase/minUpperCase/minNumber/minSymbol are all 0.'
    }
}

# --- (d) Network zones ---------------------------------------------------------
$zones = @(Get-OktaZones -Client $client)
foreach ($zone in $zones) {
    if ($null -eq $zone) { continue }
    $zoneName = [string]$zone.name
    $zoneId = [string]$zone.id
    $isReferenced = $referencedZoneIds -contains $zoneId
    if ([bool]$zone.system) {
        continue  # Okta's built-in zones (e.g. "Anywhere") are 0.0.0.0/0 by design
    }

    if ([string]$zone.status -ne 'ACTIVE') {
        # Inactive zones never match, so any rule pointing at one silently never fires.
        if ($isReferenced) {
            $findings += Add-Finding -Check 'ZONE_INACTIVE_REFERENCED' -Severity 'High' `
                -Target "Network zone '$zoneName'" `
                -Risk 'Auth-policy rules still point at this disabled zone, and disabled zones never match - those rules silently never fire.' `
                -Evidence "status=$([string]$zone.status), referenced by auth-policy rule network conditions."
        }
        continue
    }

    $gateways = @()
    if ($null -ne $zone.gateways) { $gateways = @($zone.gateways) }
    foreach ($gw in $gateways) {
        if ($null -eq $gw) { continue }
        $value = [string]$gw.value
        $m = [regex]::Match($value, '^(.+)/(\d+)$')
        if (-not $m.Success) { continue }
        $prefix = [int]$m.Groups[2].Value
        if ($prefix -lt $MinZonePrefix) {
            $sev = 'Medium'
            $refNote = ''
            if ($prefix -eq 0) { $sev = 'High' }
            if (-not $isReferenced) {
                # A broad zone nobody references is sloppy config, not an open door.
                if ($sev -eq 'High') { $sev = 'Medium' } else { $sev = 'Low' }
                $refNote = ' It is not currently referenced by any auth-policy rule.'
            }
            $findings += Add-Finding -Check 'ZONE_BROAD_GATEWAY' -Severity $sev `
                -Target "Network zone '$zoneName'" `
                -Risk "This zone treats a huge slice of the internet as trusted - any rule using it cannot tell an attacker apart from a legitimate user.$refNote" `
                -Evidence "gateway $value (prefix /$prefix is broader than /$MinZonePrefix)."
        }
    }
}

# Scariest finding first.
$ordered = @($findings | Sort-Object @{ Expression = { $sevRank[$_.Severity] }; Ascending = $true })

if ($Json) {
    $payload = $ordered | ConvertTo-Json -Depth 10
    if (-not $payload) { $payload = '[]' }
    Write-Output $payload
    if ($Output) { $payload | Out-File -FilePath $Output -Encoding utf8 }
} else {
    if ($Output -and $Output -like '*.csv') {
        $ordered | Export-Csv -Path $Output -NoTypeInformation -Encoding utf8
    } else {
        $text = 'No findings - the checked OIE posture areas look clean.'
        if ($ordered.Count -gt 0) {
            $text = $ordered | Format-Table -AutoSize | Out-String
        }
        Write-Output $text
        if ($Output) { $text | Out-File -FilePath $Output -Encoding utf8 }
    }
}
