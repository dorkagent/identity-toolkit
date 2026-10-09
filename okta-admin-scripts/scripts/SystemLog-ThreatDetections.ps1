#Requires -Version 7.0
<#
.SYNOPSIS
    A few simple detections over the Okta System Log (read-only).

.DESCRIPTION
    Same detections as system_log_threat_detections.py:

    ImpossibleTravel
        Successful user.session.start events per user in time order. Two
        sign-ins more than -MinDistanceKm apart with an implied speed above
        -MaxSpeed are flagged. Proxy traffic (securityContext.isProxy) is
        skipped and gaps under a minute count as a minute.

    PushFatigue
        -PushThreshold or more Okta Verify pushes sent to one user
        (system.push.send_factor_verify_push) within -WindowMinutes.

    MfaDeniedThenApproved
        -DenyThreshold or more MFA failures, then a success, inside the window.
        Failures are user.mfa.okta_verify.deny_push (Classic) and
        user.authentication.auth_via_mfa with outcome FAILURE (Identity
        Engine, where a mistyped code also counts).

    SessionIpChange
        One Okta session (authenticationContext.externalSessionId) seen from
        two or more IPs across user.session.start and user.authentication.sso.
        High when the locations are more than -MinDistanceKm apart, else Low.

.PARAMETER LookbackHours
    Hours of System Log to scan. Default 24.

.PARAMETER MaxSpeed
    km/h. Default 900.

.PARAMETER MinDistanceKm
    Location changes shorter than this are ignored for travel. Default 500.

.PARAMETER WindowMinutes
    Window for the MFA detections. Default 15.

.PARAMETER PushThreshold
    Pushes in the window that count as fatigue. Default 5.

.PARAMETER DenyThreshold
    MFA failures before a success that get flagged. Default 3.

.PARAMETER Json
    Print JSON instead of a table.

.PARAMETER Output
    Also write the findings to this file (JSON with -Json, otherwise CSV).

.EXAMPLE
    ./SystemLog-ThreatDetections.ps1 -LookbackHours 72 -Json -Output ./threats.json
#>
[CmdletBinding()]
param(
    [int]$LookbackHours = 24,
    [double]$MaxSpeed = 900,
    [double]$MinDistanceKm = 500,
    [int]$WindowMinutes = 15,
    [int]$PushThreshold = 5,
    [int]$DenyThreshold = 3,
    [switch]$Json,
    [string]$Output
)

Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
$ErrorActionPreference = 'Stop'
$client = New-OktaClient

function Get-HaversineKm {
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $rad = [Math]::PI / 180.0
    $a = [Math]::Pow([Math]::Sin(($Lat2 - $Lat1) * $rad / 2), 2) +
         [Math]::Cos($Lat1 * $rad) * [Math]::Cos($Lat2 * $rad) * [Math]::Pow([Math]::Sin(($Lon2 - $Lon1) * $rad / 2), 2)
    return 2 * 6371.0 * [Math]::Asin([Math]::Sqrt($a))
}

function Get-GeoPoint {
    param($LogEvent)
    $gc = $LogEvent.client.geographicalContext
    if ($null -eq $gc -or $null -eq $gc.geolocation -or $null -eq $gc.geolocation.lat -or $null -eq $gc.geolocation.lon) { return $null }
    [pscustomobject]@{ Lat = [double]$gc.geolocation.lat; Lon = [double]$gc.geolocation.lon; City = [string]$gc.city; Country = [string]$gc.country }
}

function Get-EventUser {
    # The user an event is about: the actor if it's a User, else the first User target.
    param($LogEvent)
    if (-not $LogEvent.actor.type -or $LogEvent.actor.type -eq 'User') { return $LogEvent.actor }
    $t = @($LogEvent.target) | Where-Object { $_.type -eq 'User' } | Select-Object -First 1
    if ($t) { return $t }
    return $LogEvent.actor
}

function Get-EventTime { param($LogEvent) ConvertTo-OktaUtcDate $LogEvent.published }

function Group-ByUser {
    param($LogEvents)
    $map = @{}
    foreach ($e in $LogEvents) {
        $uid = [string](Get-EventUser $e).id
        if (-not $uid) { continue }
        if (-not $map.ContainsKey($uid)) { $map[$uid] = [System.Collections.Generic.List[object]]::new() }
        $map[$uid].Add($e)
    }
    foreach ($k in @($map.Keys)) { $map[$k] = @($map[$k] | Sort-Object { Get-EventTime $_ }) }
    return $map
}

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($LogEvent, [string]$Type, [string]$Severity, [string]$Detail)
    $u = Get-EventUser $LogEvent
    $name = if ($u.alternateId) { [string]$u.alternateId } else { [string]$u.id }
    $script:findings.Add([pscustomobject]@{ Time = (ConvertTo-OktaIsoString $LogEvent.published); User = $name; Type = $Type; Severity = $Severity; Detail = $Detail })
}

$since = [datetime]::UtcNow.AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$types = 'user.session.start', 'user.authentication.sso', 'system.push.send_factor_verify_push', 'user.mfa.okta_verify.deny_push', 'user.authentication.auth_via_mfa'
$filter = ($types | ForEach-Object { "eventType eq `"$_`"" }) -join ' or '
$events = @(Get-OktaLogs -Client $client -Filter $filter -Since $since)
$window = [TimeSpan]::FromMinutes($WindowMinutes)

# Impossible travel
$signIns = @($events | Where-Object {
    $_.eventType -eq 'user.session.start' -and $_.outcome.result -eq 'SUCCESS' -and -not $_.securityContext.isProxy -and (Get-GeoPoint $_)
})
$byUser = Group-ByUser $signIns
foreach ($list in $byUser.Values) {
    for ($i = 1; $i -lt $list.Count; $i++) {
        $g1 = Get-GeoPoint $list[$i - 1]; $g2 = Get-GeoPoint $list[$i]
        $km = Get-HaversineKm $g1.Lat $g1.Lon $g2.Lat $g2.Lon
        if ($km -lt $MinDistanceKm) { continue }
        $hours = [Math]::Max(((Get-EventTime $list[$i]) - (Get-EventTime $list[$i - 1])).TotalSeconds, 60) / 3600
        $speed = $km / $hours
        if ($speed -gt $MaxSpeed) {
            Add-Finding $list[$i] 'ImpossibleTravel' 'High' ('{0:N0} km in {1:N2} h ({2:N0} km/h): {3}, {4} -> {5}, {6}' -f $km, $hours, $speed, $g1.City, $g1.Country, $g2.City, $g2.Country)
        }
    }
}

# Push fatigue
$byUser = Group-ByUser @($events | Where-Object { $_.eventType -eq 'system.push.send_factor_verify_push' })
foreach ($list in $byUser.Values) {
    $start = 0
    for ($j = 0; $j -lt $list.Count; $j++) {
        while (((Get-EventTime $list[$j]) - (Get-EventTime $list[$start])) -gt $window) { $start++ }
        if ($j - $start + 1 -ge $PushThreshold) {
            Add-Finding $list[$j] 'PushFatigue' 'High' ('{0} pushes sent in {1} min' -f ($j - $start + 1), $WindowMinutes)
            break
        }
    }
}

# MFA denied then approved
$byUser = Group-ByUser @($events | Where-Object { $_.eventType -in 'user.mfa.okta_verify.deny_push', 'user.authentication.auth_via_mfa' })
foreach ($list in $byUser.Values) {
    $failures = [System.Collections.Generic.List[datetime]]::new()
    foreach ($e in $list) {
        $t = Get-EventTime $e
        $recent = @($failures | Where-Object { ($t - $_) -le $window })
        $failures = [System.Collections.Generic.List[datetime]]::new()
        foreach ($f in $recent) { $failures.Add($f) }
        $isFailure = $e.eventType -eq 'user.mfa.okta_verify.deny_push' -or ($e.eventType -eq 'user.authentication.auth_via_mfa' -and $e.outcome.result -eq 'FAILURE')
        if ($isFailure) { $failures.Add($t) }
        elseif ($e.outcome.result -eq 'SUCCESS' -and $failures.Count -ge $DenyThreshold) {
            Add-Finding $e 'MfaDeniedThenApproved' 'High' ('{0} MFA failures then a success within {1} min' -f $failures.Count, $WindowMinutes)
            break
        }
    }
}

# Session used from several IPs
$sessions = @{}
foreach ($e in $events | Where-Object { $_.eventType -in 'user.session.start', 'user.authentication.sso' }) {
    $sid = [string]$e.authenticationContext.externalSessionId
    if (-not $sid -or $sid -eq 'unknown') { continue }
    if (-not $sessions.ContainsKey($sid)) { $sessions[$sid] = [System.Collections.Generic.List[object]]::new() }
    $sessions[$sid].Add($e)
}
foreach ($sid in $sessions.Keys) {
    $list = @($sessions[$sid] | Sort-Object { Get-EventTime $_ })
    $ips = @($list | ForEach-Object { [string]$_.client.ipAddress } | Where-Object { $_ } | Sort-Object -Unique)
    if ($ips.Count -lt 2) { continue }
    $geos = @($list | Where-Object { -not $_.securityContext.isProxy } | ForEach-Object { Get-GeoPoint $_ } | Where-Object { $_ })
    $far = 0.0
    for ($a = 0; $a -lt $geos.Count; $a++) {
        for ($b = $a + 1; $b -lt $geos.Count; $b++) {
            $far = [Math]::Max($far, (Get-HaversineKm $geos[$a].Lat $geos[$a].Lon $geos[$b].Lat $geos[$b].Lon))
        }
    }
    $sev = if ($far -ge $MinDistanceKm) { 'High' } else { 'Low' }
    $shortSid = $sid.Substring(0, [Math]::Min(10, $sid.Length))
    $detail = "session $shortSid... used from $($ips.Count) IPs ($(($ips | Select-Object -First 4) -join ', '))"
    if ($far -gt 0) { $detail += (', up to {0:N0} km apart' -f $far) }
    Add-Finding $list[0] 'SessionIpChange' $sev $detail
}

$sorted = @($findings | Sort-Object Time, Type)
if ($Json) {
    $text = ConvertTo-Json -InputObject $sorted -Depth 5
    Write-Output $text
    if ($Output) { $text | Out-File -LiteralPath $Output -Encoding utf8 }
} else {
    $sorted | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Output
    Write-Output "$($sorted.Count) findings from $($events.Count) events since $since"
    if ($Output) { $sorted | Export-OktaCsv -Path $Output }
}
