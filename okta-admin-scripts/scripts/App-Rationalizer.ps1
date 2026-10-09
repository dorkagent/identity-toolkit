#Requires -Version 7.0
<#
.SYNOPSIS
    Ranks Okta apps by recent login activity and flags duplicates and removal candidates.

.DESCRIPTION
    Read-only. Lists all Okta apps (Get-OktaApps), then makes a single pass over the
    System Log for user.authentication.sso events to tally sign-ins per app
    over -LookbackDays (90 days at most; that is all Okta keeps). For each app it also counts assigned users (Get-OktaAppUsers)
    and computes three kinds of duplication flags:

      DuplicateLabel   two or more apps share the same normalized label
                       (lowercased, non-alphanumeric characters stripped)
      NearDuplicate    label word-set similarity (Jaccard index over the
                       whitespace/token word sets) >= -Similarity
      VendorDup        two or more app instances share the same vendor
                       (the app's "name" field, e.g. "salesforce")

    An app is flagged as a RemovalCandidate when it has zero logins in the
    lookback window AND zero assigned users. Output is ranked by login count
    (descending), then assigned-user count (descending).

    Table output by default; -Json for machine-readable output; -Output also
    writes the report to a file (JSON with -Json, otherwise CSV).

.PARAMETER LookbackDays
    How many days back to scan the System Log for logins. Default 90.

.PARAMETER Similarity
    Word-set similarity threshold (0.0-1.0) for the NearDuplicate flag.
    Default 0.8.

.PARAMETER Limit
    Show only the top N rows after ranking. 0 (default) means no limit.

.PARAMETER Json
    Emit the report as JSON instead of a table.

.PARAMETER Output
    Write the report to this file path as well as displaying it.

.EXAMPLE
    .\App-Rationalizer.ps1
    Rank all apps by logins over the last 90 days.

.EXAMPLE
    .\App-Rationalizer.ps1 -LookbackDays 30 -Limit 25 -Json -Output .\rationalizer.json
    Top 25 apps by logins over the last 30 days, as JSON, saved to a file.
#>

[CmdletBinding()]
param(
    [int]$LookbackDays = 90,
    [double]$Similarity = 0.8,
    [int]$Limit = 0,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

function Get-NormalizedLabel {
    param([string]$Label)
    if (-not $Label) { return "" }
    return ([regex]::Replace($Label.ToLowerInvariant(), "[^a-z0-9]", ""))
}

function Get-LabelWords {
    param([string]$Label)
    if (-not $Label) { return @() }
    $clean = [regex]::Replace($Label.ToLowerInvariant(), "[^a-z0-9]+", " ").Trim()
    if ($clean -eq "") { return @() }
    return @($clean -split "\s+" | Select-Object -Unique)
}

function Get-WordOverlap {
    param([string[]]$A, [string[]]$B)
    if ($A.Count -eq 0 -or $B.Count -eq 0) { return 0.0 }
    $setA = @{}
    foreach ($w in $A) { $setA[$w] = $true }
    $shared = 0
    foreach ($w in $B) { if ($setA.ContainsKey($w)) { $shared++ } }
    $union = @{}
    foreach ($w in $A) { $union[$w] = $true }
    foreach ($w in $B) { $union[$w] = $true }
    if ($union.Count -eq 0) { return 0.0 }
    return [double]$shared / [double]$union.Count
}

# --- Collect apps ------------------------------------------------------------
$apps = @(Get-OktaApps -Client $client)
if ($apps.Count -eq 0) {
    Write-Warning "No apps returned from the tenant."
    exit 0
}

$appIds = @{}
foreach ($a in $apps) { $appIds[[string]$a.id] = $a }

# --- Single pass over the System Log: tally logins per app -------------------
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
# user.session.start targets the user, not an app, so only SSO events count.
$filter = 'eventType eq "user.authentication.sso"'
$logins = @{}
foreach ($e in (Get-OktaLogs -Client $client -Filter $filter -Since $cutoff)) {
    foreach ($t in @($e.target)) {
        $tid = [string]$t.id
        if ($tid -and $appIds.ContainsKey($tid)) {
            if (-not $logins.ContainsKey($tid)) { $logins[$tid] = 0 }
            $logins[$tid]++
        }
    }
}

# --- Assigned users per app --------------------------------------------------
$assigned = @{}
foreach ($a in $apps) {
    $assigned[[string]$a.id] = @((Get-OktaAppUsers -Client $client -AppId ([string]$a.id))).Count
}

# --- Duplicate detection ------------------------------------------------------
# Exact duplicate: normalized label (lowercase, strip non-alphanumeric)
$normGroups = @{}
for ($i = 0; $i -lt $apps.Count; $i++) {
    $n = Get-NormalizedLabel ([string]$apps[$i].label)
    if (-not $normGroups.ContainsKey($n)) { $normGroups[$n] = New-Object System.Collections.ArrayList }
    [void]$normGroups[$n].Add($i)
}
$dupIndex = @{}
foreach ($n in $normGroups.Keys) {
    if ($normGroups[$n].Count -gt 1) {
        foreach ($i in $normGroups[$n]) { $dupIndex[$i] = $true }
    }
}

# Near duplicate: word-set overlap (Jaccard) >= -Similarity
$wordSets = New-Object System.Collections.ArrayList
foreach ($a in $apps) { [void]$wordSets.Add(@(Get-LabelWords ([string]$a.label))) }
$nearIndex = @{}
for ($i = 0; $i -lt $apps.Count; $i++) {
    for ($j = $i + 1; $j -lt $apps.Count; $j++) {
        if ($dupIndex.ContainsKey($i) -and $dupIndex.ContainsKey($j)) { continue }
        if ((Get-WordOverlap $wordSets[$i] $wordSets[$j]) -ge $Similarity) {
            $nearIndex[$i] = $true
            $nearIndex[$j] = $true
        }
    }
}

# Vendor duplicate: same app vendor ("name") with multiple instances
$vendorGroups = @{}
for ($i = 0; $i -lt $apps.Count; $i++) {
    $v = [string]$apps[$i].name
    if (-not $v) { $v = "(none)" }
    if (-not $vendorGroups.ContainsKey($v)) { $vendorGroups[$v] = New-Object System.Collections.ArrayList }
    [void]$vendorGroups[$v].Add($i)
}
$vendorIndex = @{}
foreach ($v in $vendorGroups.Keys) {
    if ($vendorGroups[$v].Count -gt 1) {
        foreach ($i in $vendorGroups[$v]) { $vendorIndex[$i] = $true }
    }
}

# --- Build ranked rows --------------------------------------------------------
$rows = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $apps.Count; $i++) {
    $a = $apps[$i]
    $id = [string]$a.id
    $loginCount = 0
    if ($logins.ContainsKey($id)) { $loginCount = $logins[$id] }
    $assignedCount = $assigned[$id]
    $flags = @()
    if ($dupIndex.ContainsKey($i)) { $flags += "DuplicateLabel" }
    if ($nearIndex.ContainsKey($i)) { $flags += "NearDuplicate" }
    if ($vendorIndex.ContainsKey($i)) { $flags += "VendorDup" }
    if ($loginCount -eq 0 -and $assignedCount -eq 0) { $flags += "RemovalCandidate" }
    [void]$rows.Add([pscustomobject]@{
        App      = [string]$a.label
        Vendor   = [string]$a.name
        Logins   = $loginCount
        Assigned = $assignedCount
        Flags    = ($flags -join ", ")
    })
}

$sorted = @($rows | Sort-Object -Property @{ Expression = "Logins"; Descending = $true }, @{ Expression = "Assigned"; Descending = $true })
if ($Limit -gt 0) { $sorted = @($sorted | Select-Object -First $Limit) }

# --- Output -------------------------------------------------------------------
if ($Json) {
    $text = $sorted | ConvertTo-Json -Depth 5
    if ($Output) { $text | Out-File -FilePath $Output -Encoding utf8 }
    Write-Output $text
}
else {
    if ($Output) { $sorted | Export-OktaCsv -Path $Output }
    $sorted | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
}
