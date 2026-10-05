<#
.SYNOPSIS
    Detects authentication threats in the Okta System Log: impossible travel,
    MFA fatigue, and session/token anomalies.

.DESCRIPTION
    Read-only. Scans the System Log over -LookbackHours and runs three detectors:

    (a) Impossible travel: user.session.start events grouped per user and sorted
        by time. For consecutive events carrying geolocation
        ($e.client.geographicalContext.geolocation), the haversine distance
        divided by elapsed hours gives an implied travel speed; speeds above
        -MaxSpeed (default 900 km/h) are flagged with the cities and timestamps.

    (b) MFA fatigue: events of type -MfaEvent (default
        "user.authentication.auth_via_mfa") grouped per user. A sliding window
        of -FatigueWindowMinutes (default 15) containing at least
        -FatigueThreshold (default 10) attempts is flagged. Also flags a
        denied-then-approved pattern (outcome.result FAILURE followed by
        SUCCESS within the same window) for the same user.

    (c) Token replay / session anomalies: the session id is taken from
        $e.target[0].id on session-start events. Flags a session id seen from
        2+ distinct IPs, or from geolocations more than -MinDistanceKm
        (default 500) apart. Also flags concurrent sessions for the same user:
        events from different session ids within -ConcurrencyWindowMinutes
        (default 60) whose geolocations are more than -MinDistanceKm apart.

    NOTE: Okta Verify / push event types vary by org version; the exact event
    type for MFA challenges may differ on your tenant. Use -MfaEvent to override
    the event type used for detector (b).

    Findings table: Time, User, Type, Detail, Severity. -Json for
    machine-readable output; -Output writes the report to a file. Requires
    OKTA_DOMAIN and OKTA_API_TOKEN environment variables. Secrets are never
    hardcoded.

.PARAMETER LookbackHours
    How many hours back to scan the System Log. Default 24.

.PARAMETER MaxSpeed
    Implied travel speed (km/h) above which a consecutive event pair is
    flagged as impossible travel. Default 900.

.PARAMETER MfaEvent
    System Log event type used for MFA challenge detection. Default
    "user.authentication.auth_via_mfa". Override this if your org version
    emits Okta Verify / push events under a different type.

.PARAMETER FatigueWindowMinutes
    Sliding-window size in minutes for MFA fatigue detection. Default 15.

.PARAMETER FatigueThreshold
    Number of MFA attempts within the fatigue window that triggers a flag.
    Default 10.

.PARAMETER MinDistanceKm
    Minimum haversine distance (km) between geolocations that counts as
    "distant" for session anomaly detection. Default 500.

.PARAMETER ConcurrencyWindowMinutes
    Time window in minutes used to detect concurrent distant sessions for
    the same user. Default 60.

.PARAMETER Json
    Emit the findings as JSON instead of a table.

.PARAMETER Output
    Write the report to this file path as well as displaying it.

.EXAMPLE
    .\SystemLog-ThreatDetections.ps1
    Run all detectors over the last 24 hours of System Log events.

.EXAMPLE
    .\SystemLog-ThreatDetections.ps1 -LookbackHours 72 -MfaEvent "user.authentication.auth_via_push" -Json -Output .\threats.json
    Scan 72 hours using a custom MFA event type, save findings as JSON.
#>

[CmdletBinding()]
param(
    [int]$LookbackHours = 24,
    [double]$MaxSpeed = 900,
    [string]$MfaEvent = "user.authentication.auth_via_mfa",
    [int]$FatigueWindowMinutes = 15,
    [int]$FatigueThreshold = 10,
    [double]$MinDistanceKm = 500,
    [int]$ConcurrencyWindowMinutes = 60,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$client = New-OktaClient

function Get-HaversineKm {
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $rad = [Math]::PI / 180.0
    $dLat = ($Lat2 - $Lat1) * $rad
    $dLon = ($Lon2 - $Lon1) * $rad
    $sinLat = [Math]::Sin($dLat / 2)
    $sinLon = [Math]::Sin($dLon / 2)
    $a = ($sinLat * $sinLat) + ([Math]::Cos($Lat1 * $rad) * [Math]::Cos($Lat2 * $rad) * $sinLon * $sinLon)
    $c = 2 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a))
    return 6371.0 * $c
}

function Get-GeoPoint {
    param($LogEvent)
    $g = $LogEvent.client.geographicalContext.geolocation
    if ($null -eq $g) { return $null }
    if ($null -eq $g.lat -or $null -eq $g.lon) { return $null }
    return [pscustomobject]@{
        Lat     = [double]$g.lat
        Lon     = [double]$g.lon
        City    = [string]$g.city
        Country = [string]$g.country
    }
}

function Get-EventLogin {
    param($LogEvent)
    $login = [string]$LogEvent.actor.alternateId
    if (-not $login) { $login = [string]$LogEvent.actor.id }
    return $login
}

function Get-SessionId {
    param($LogEvent)
    $t0 = @($LogEvent.target)[0]
    if ($null -eq $t0) { return "" }
    return [string]$t0.id
}

$findings = New-Object System.Collections.ArrayList
function Add-Finding {
    param([datetime]$Time, [string]$User, [string]$Type, [string]$Detail, [string]$Severity)
    [void]$script:findings.Add([pscustomobject]@{
        Time     = $Time
        User     = $User
        Type     = $Type
        Detail   = $Detail
        Severity = $Severity
    })
}

$cutoff = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

# --- (a) Impossible travel ----------------------------------------------------
$sessionEvents = @(Get-OktaLogs -Client $client -Filter 'eventType eq "user.session.start"' -Since $cutoff)

$byUser = @{}
foreach ($e in $sessionEvents) {
    $login = Get-EventLogin $e
    if (-not $byUser.ContainsKey($login)) { $byUser[$login] = New-Object System.Collections.ArrayList }
    [void]$byUser[$login].Add($e)
}

foreach ($login in $byUser.Keys) {
    $list = @($byUser[$login] | Sort-Object -Property { [datetime]$_.published })
    for ($i = 1; $i -lt $list.Count; $i++) {
        $prev = $list[$i - 1]
        $cur = $list[$i]
        $g1 = Get-GeoPoint $prev
        $g2 = Get-GeoPoint $cur
        if ($null -eq $g1 -or $null -eq $g2) { continue }
        $t1 = [datetime]$prev.published
        $t2 = [datetime]$cur.published
        $hours = ($t2 - $t1).TotalHours
        if ($hours -le 0) { continue }
        $km = Get-HaversineKm -Lat1 $g1.Lat -Lon1 $g1.Lon -Lat2 $g2.Lat -Lon2 $g2.Lon
        $speed = $km / $hours
        if ($speed -gt $MaxSpeed) {
            $detail = "{0} -> {1}: {2:N0} km in {3:N1}h (implied {4:N0} km/h, limit {5:N0})" -f $g1.City, $g2.City, $km, $hours, $speed, $MaxSpeed
            Add-Finding -Time $t2 -User $login -Type "ImpossibleTravel" -Detail $detail -Severity "High"
        }
    }
}

# --- (b) MFA fatigue ----------------------------------------------------------
$mfaEvents = @(Get-OktaLogs -Client $client -Filter "eventType eq `"$MfaEvent`"" -Since $cutoff)

$byMfaUser = @{}
foreach ($e in $mfaEvents) {
    $login = Get-EventLogin $e
    if (-not $byMfaUser.ContainsKey($login)) { $byMfaUser[$login] = New-Object System.Collections.ArrayList }
    [void]$byMfaUser[$login].Add($e)
}

$fatigueWindow = [TimeSpan]::FromMinutes($FatigueWindowMinutes)
foreach ($login in $byMfaUser.Keys) {
    $list = @($byMfaUser[$login] | Sort-Object -Property { [datetime]$_.published })
    $times = @()
    foreach ($e in $list) { $times += [datetime]$e.published }

    # Sliding window: >= threshold attempts within the window
    $flagged = $false
    for ($i = 0; $i -lt $times.Count -and -not $flagged; $i++) {
        $count = 0
        for ($j = $i; $j -lt $times.Count; $j++) {
            if (($times[$j] - $times[$i]) -le $fatigueWindow) { $count++ } else { break }
        }
        if ($count -ge $FatigueThreshold) {
            $detail = "{0} MFA attempts within {1} minutes (threshold {2})" -f $count, $FatigueWindowMinutes, $FatigueThreshold
            Add-Finding -Time $times[$i] -User $login -Type "MfaFatigue" -Detail $detail -Severity "High"
            $flagged = $true
        }
    }

    # Denied-then-approved: FAILURE followed by SUCCESS within the window
    $deniedFlagged = $false
    for ($i = 0; $i -lt $list.Count -and -not $deniedFlagged; $i++) {
        if ([string]$list[$i].outcome.result -ne "FAILURE") { continue }
        $tFail = [datetime]$list[$i].published
        for ($k = $i + 1; $k -lt $list.Count; $k++) {
            $tK = [datetime]$list[$k].published
            if (($tK - $tFail) -gt $fatigueWindow) { break }
            if ([string]$list[$k].outcome.result -eq "SUCCESS") {
                $detail = "MFA denied at {0:u} then approved at {1:u} within {2} minutes" -f $tFail, $tK, $FatigueWindowMinutes
                Add-Finding -Time $tK -User $login -Type "MfaDeniedThenApproved" -Detail $detail -Severity "Medium"
                $deniedFlagged = $true
                break
            }
        }
    }
}

# --- (c) Session / token anomalies --------------------------------------------
$bySession = @{}
foreach ($e in $sessionEvents) {
    $sid = Get-SessionId $e
    if (-not $sid) { continue }
    if (-not $bySession.ContainsKey($sid)) { $bySession[$sid] = New-Object System.Collections.ArrayList }
    [void]$bySession[$sid].Add($e)
}

foreach ($sid in $bySession.Keys) {
    $list = @($bySession[$sid])
    $login = Get-EventLogin $list[0]
    $firstTime = [datetime]$list[0].published

    # Same session id from 2+ distinct IPs
    $ips = @{}
    foreach ($e in $list) {
        $ip = [string]$e.client.ipAddress
        if ($ip) { $ips[$ip] = $true }
    }
    if ($ips.Count -ge 2) {
        $detail = "Session {0} seen from {1} distinct IPs: {2}" -f $sid, $ips.Count, (($ips.Keys | Sort-Object) -join ", ")
        Add-Finding -Time $firstTime -User $login -Type "SessionIpReuse" -Detail $detail -Severity "Medium"
    }

    # Same session id from distant geolocations
    $geos = @()
    foreach ($e in $list) {
        $g = Get-GeoPoint $e
        if ($null -ne $g) { $geos += $g }
    }
    $maxDist = 0.0
    for ($i = 0; $i -lt $geos.Count; $i++) {
        for ($j = $i + 1; $j -lt $geos.Count; $j++) {
            $d = Get-HaversineKm -Lat1 $geos[$i].Lat -Lon1 $geos[$i].Lon -Lat2 $geos[$j].Lat -Lon2 $geos[$j].Lon
            if ($d -gt $maxDist) { $maxDist = $d }
        }
    }
    if ($maxDist -gt $MinDistanceKm) {
        $detail = "Session {0} used from locations {1:N0} km apart (threshold {2:N0} km)" -f $sid, $maxDist, $MinDistanceKm
        Add-Finding -Time $firstTime -User $login -Type "SessionGeoSpread" -Detail $detail -Severity "Medium"
    }
}

# Concurrent sessions: same user, different session ids, within the
# concurrency window, from distant geolocations
$concurrencyWindow = [TimeSpan]::FromMinutes($ConcurrencyWindowMinutes)
foreach ($login in $byUser.Keys) {
    $list = @($byUser[$login] | Sort-Object -Property { [datetime]$_.published })
    $reported = $false
    for ($i = 0; $i -lt $list.Count -and -not $reported; $i++) {
        $gi = Get-GeoPoint $list[$i]
        if ($null -eq $gi) { continue }
        $si = Get-SessionId $list[$i]
        $tI = [datetime]$list[$i].published
        for ($k = $i + 1; $k -lt $list.Count; $k++) {
            $tK = [datetime]$list[$k].published
            if (($tK - $tI) -gt $concurrencyWindow) { break }
            $sk = Get-SessionId $list[$k]
            if ($sk -eq $si) { continue }
            $gk = Get-GeoPoint $list[$k]
            if ($null -eq $gk) { continue }
            $d = Get-HaversineKm -Lat1 $gi.Lat -Lon1 $gi.Lon -Lat2 $gk.Lat -Lon2 $gk.Lon
            if ($d -gt $MinDistanceKm) {
                $detail = "Sessions {0} and {1} active {2:N0} km apart within {3} minutes ({4} / {5})" -f $si, $sk, $d, $ConcurrencyWindowMinutes, $gi.City, $gk.City
                Add-Finding -Time $tK -User $login -Type "ConcurrentDistantSessions" -Detail $detail -Severity "Medium"
                $reported = $true
                break
            }
        }
    }
}

# --- Output -------------------------------------------------------------------
$sorted = @($findings | Sort-Object -Property Time -Descending)

if ($Json) {
    $text = $sorted | ConvertTo-Json -Depth 10
    if ($Output) { $text | Out-File -FilePath $Output -Encoding utf8 }
    Write-Output $text
}
else {
    if ($Output) { $sorted | Format-Table -AutoSize | Out-String | Out-File -FilePath $Output -Encoding utf8 }
    $sorted | Format-Table -AutoSize
}
