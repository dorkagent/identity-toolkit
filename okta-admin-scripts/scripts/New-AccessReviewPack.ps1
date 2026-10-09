#Requires -Version 7.0
<#
.SYNOPSIS
    Builds per-app access review CSV packs for a basic manager certification.

.DESCRIPTION
    For every ACTIVE app in the tenant, exports its assignments to a CSV with
    one row per assignment: the user's login, display name, manager,
    assignment type (Direct or Group), last login, and review flags.

    Each assignment's user is resolved (GET /api/v1/users/{id}) to pull the
    profile manager (profile.manager, falling back to profile.managerId) and
    lastLogin. Assignments are flagged for reviewer attention when:

      - DORMANT:            lastLogin older than -DormantDays (default 90)
      - NEVER_LOGGED_IN:    the user has no lastLogin at all
      - DIRECT_ASSIGNMENT:   scope is USER (assigned directly, not via a group)

    Output: one CSV per app in $OutputDir (filename sanitized from the app
    label), a REVIEW-GUIDE.md explaining the quarterly review cycle in plain
    language, and a _SUMMARY.csv rollup. The console prints the rollup table
    sorted by risk so the riskiest apps are obvious at a glance.

    The rollup's RiskScore weights what reviewers care about most:
        RiskScore = DirectCount + 2 x DormantCount + 3 x NeverLoggedInCount
    Never-logged-in accounts score highest because they are the most common
    source of orphaned access; direct assignments score per-row because they
    bypass group governance.

    Read-only: every call is a GET.

    LastLogin is the user's last Okta sign-in, not their last use of this
    app. For per-app last use, check the Application Usage report or the
    System Log (user.authentication.sso per app).

    CSV cells that start with = + - @ are prefixed with a quote so a profile
    field can't run as a formula when a reviewer opens the file in Excel.

.PARAMETER OutputDir
    Directory the review pack is written to. Default:
    "review-packs-yyyyMMdd" (today's date), created if missing.

.PARAMETER DormantDays
    Last-login age in days beyond which an assignment is flagged DORMANT.
    Default 90. Never-logged-in users are flagged regardless of this value.

.PARAMETER Limit
    Maximum assignment rows written per app CSV (a smoke-test switch).
    0 (default) = no limit.

.PARAMETER Json
    Emit the rollup as JSON on the console instead of a table. The CSV files
    (per-app packs and _SUMMARY.csv) are written either way.

.EXAMPLE
    pwsh ./New-AccessReviewPack.ps1
    Builds the full review pack into ./review-packs-20260928/ and prints the
    risk-sorted rollup table.

.EXAMPLE
    pwsh ./New-AccessReviewPack.ps1 -DormantDays 60 -OutputDir ./q3-review
    Flags anything idle 60+ days and writes the pack into ./q3-review/.

.EXAMPLE
    pwsh ./New-AccessReviewPack.ps1 -Limit 5 -Json
    Writes at most 5 rows per app CSV and prints the rollup as JSON.
#>

param(
    [string]$OutputDir = "review-packs-$(Get-Date -Format 'yyyyMMdd')",
    [int]$DormantDays = 90,
    [int]$Limit = 0,
    [switch]$Json
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

function Get-SafeFileName {
    <#
    .SYNOPSIS
        Turn an app label into a filesystem-safe CSV stem.
    #>
    param([string]$Label)
    $safe = $Label -replace '[<>:"/\\|?*]', '_'
    $safe = $safe -replace '\s+', ' '
    $safe = $safe.Trim().Trim('.')
    if (-not $safe) { $safe = 'unnamed-app' }
    if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
    return $safe
}

function Get-AppUserLoginRows {
    <#
    .SYNOPSIS
        Build the review rows for one app's assignments. GET-only.
    #>
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [Parameter(Mandatory)][psobject]$App,
        [datetime]$Cutoff
    )
    $rows = @()
    $assignments = @(Get-OktaAppUsers -Client $Client -AppId $App.id)
    foreach ($assignment in $assignments) {
        $isDirect = ($assignment.scope -eq 'USER')
        $assignmentType = if ($isDirect) { 'Direct' } else { 'Group' }

        $user = $null
        $userHref = $assignment._links.user.href
        if ($userHref) {
            try {
                $userPath = ([uri]$userHref).AbsolutePath
                $user = Invoke-OktaRequest -Client $Client -Method GET -Path $userPath
            } catch {
                $user = $null
            }
        }

        $login = $null
        $name = $null
        $manager = $null
        $lastLoginRaw = $null
        if ($user) {
            $login = $user.profile.login
            $name = (@($user.profile.firstName, $user.profile.lastName) -join ' ').Trim()
            if (-not $name) { $name = $login }
            $manager = $user.profile.manager ?? $user.profile.managerId
            $lastLoginRaw = $user.lastLogin
        } else {
            $login = if ($assignment.externalId) { $assignment.externalId } else { '(unresolved)' }
        }

        $neverLoggedIn = ($null -eq $lastLoginRaw) -or ('' -eq "$lastLoginRaw")
        $flags = @()
        $daysInactive = $null
        $lastLoginDisplay = 'never'
        if ($neverLoggedIn) {
            $flags += 'NEVER_LOGGED_IN'
        } else {
            $lastLogin = [datetime]$lastLoginRaw
            $lastLoginDisplay = $lastLogin.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            if ($lastLogin -lt $Cutoff) {
                $flags += 'DORMANT'
                $daysInactive = [int]((Get-Date).ToUniversalTime().Subtract($lastLogin).TotalDays)
            }
        }
        if ($isDirect) { $flags += 'DIRECT_ASSIGNMENT' }
        if (-not $user) { $flags += 'UNRESOLVED_USER' }

        $rows += [pscustomobject]@{
            App             = $App.label
            Login           = $login
            Name            = $name
            Manager         = $manager
            AssignmentType  = $assignmentType
            LastLogin       = $lastLoginDisplay
            DaysInactive    = $daysInactive
            ReviewFlag      = ($flags -join '; ')
            Dormant         = ($flags -contains 'DORMANT') -or ($flags -contains 'NEVER_LOGGED_IN')
            Direct          = $isDirect
            NeverLoggedIn   = $neverLoggedIn
        }
    }
    return $rows
}

$cutoff = (Get-Date).ToUniversalTime().AddDays(-$DormantDays)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$summary = @()
$apps = @(Get-OktaApps -Client $client) | Where-Object { $_.status -eq 'ACTIVE' }
foreach ($app in $apps) {
    $rows = @(Get-AppUserLoginRows -Client $client -App $app -Cutoff $cutoff)
    if ($Limit -gt 0 -and $rows.Count -gt $Limit) { $rows = $rows[0..($Limit - 1)] }

    $fileName = "$(Get-SafeFileName -Label "$($app.label)").csv"
    $csvPath = Join-Path $OutputDir $fileName
    if ($rows.Count -gt 0) {
        $rows | Select-Object App, Login, Name, Manager, AssignmentType, LastLogin,
            DaysInactive, ReviewFlag | Export-OktaCsv -Path $csvPath
    } else {
        'App,Login,Name,Manager,AssignmentType,LastLogin,DaysInactive,ReviewFlag' |
            Out-File -FilePath $csvPath -Encoding utf8
    }

    $dormantCount = @($rows | Where-Object { $_.Dormant }).Count
    $directCount = @($rows | Where-Object { $_.Direct }).Count
    $neverCount = @($rows | Where-Object { $_.NeverLoggedIn }).Count
    $dormantOnly = $dormantCount - $neverCount
    # Never-logged-in rows are already counted inside $dormantCount, so use
    # the dormant-only remainder to match the documented formula:
    #   DirectCount + 2 x DormantCount + 3 x NeverLoggedInCount
    $riskScore = $directCount + (2 * $dormantOnly) + (3 * $neverCount)

    $summary += [pscustomobject]@{
        App             = $app.label
        AppId           = $app.id
        CsvFile         = $fileName
        Assignments     = $rows.Count
        DirectCount     = $directCount
        DormantCount    = $dormantOnly
        NeverLoggedIn   = $neverCount
        RiskScore       = $riskScore
    }
}

$summary = @($summary | Sort-Object -Property RiskScore -Descending)
$summary | Select-Object App, Assignments, DirectCount, DormantCount,
    NeverLoggedIn, RiskScore, CsvFile |
    Export-OktaCsv -Path (Join-Path $OutputDir '_SUMMARY.csv')

$guide = @'
# Access Review Guide

This folder is a review pack: one CSV per application listing who has access,
plus a `_SUMMARY.csv` rollup, for a basic quarterly access certification.
Generating it changed nothing in Okta.

## The quarterly review cycle

1. **Generate the pack.** Run `pwsh ./New-AccessReviewPack.ps1`. A new
   `review-packs-<date>/` folder appears with one CSV per app.
2. **Start with the rollup.** Open `_SUMMARY.csv`. It is sorted by RiskScore,
   so the riskiest apps are at the top. Assign each app's CSV to its owner;
   usually the app's business owner or the reporter's manager, not IT.
3. **Review each CSV.** The reviewer goes row by row and marks each assignment
   APPROVE (keep access) or REVOKE (remove access), ideally in a copy of the
   CSV with an added "Decision" column.
4. **Pay attention to the flags.** Rows with a `ReviewFlag` need a real
   decision, not a rubber stamp:
   - `DORMANT` / `NEVER_LOGGED_IN`: the person hasn't signed in to Okta
     recently (or ever). That is about Okta as a whole, not this app, but it
     is a strong hint the access isn't needed. Ask before keeping it.
   - `DIRECT_ASSIGNMENT`; the user was given access individually instead of
     through a group. Ask: should this be a group membership instead?
   - `UNRESOLVED_USER`; the assignment points at a user that no longer
     resolves. Almost always safe to REVOKE; treat it as cleanup.
   - No flag; routine access. Verify the person still needs the app, then
     APPROVE.
5. **Record the outcome.** Keep the reviewed CSVs and the reviewer's decisions
   somewhere auditors can find them (a ticket, a shared drive, Confluence).
   That paper trail is what auditors actually ask for: who had access, who
   approved it, and when.
6. **Act on revocations.** Removing access is a separate step; do it through
   the normal deprovisioning process, not from this pack.

Repeat quarterly. A good rhythm is one week per quarter: day 1 generate and
assign, days 2-4 reviews come back, day 5 record and close out.

## How to read a review CSV

| Column | Meaning |
|---|---|
| App | The application being reviewed |
| Login | The user's login |
| Name | The user's display name |
| Manager | The user's manager from their Okta profile (blank if not set) |
| AssignmentType | `Direct` = assigned to the user individually; `Group` = inherited from a group |
| LastLogin | The user's most recent Okta login, or `never` |
| DaysInactive | Days since last login (dormant accounts only) |
| ReviewFlag | Attention flags, separated by `; ` (blank means routine) |

## About the RiskScore

`RiskScore = DirectCount + 2 x DormantCount + 3 x NeverLoggedInCount`.
Never-logged-in accounts score highest; they are the most common source of
orphaned access. Direct assignments score per row because they bypass group
governance. The score is a triage aid, not a verdict: an app can be risky for
legitimate reasons, and a low score is not a clean bill of health.
'@
$guide | Out-File -FilePath (Join-Path $OutputDir 'REVIEW-GUIDE.md') -Encoding utf8

if ($Json) {
    $payload = $summary | ConvertTo-Json -Depth 5
    if ($payload) { Write-Output $payload }
} else {
    $summary | Select-Object App, Assignments, DirectCount, DormantCount,
        NeverLoggedIn, RiskScore | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
}
