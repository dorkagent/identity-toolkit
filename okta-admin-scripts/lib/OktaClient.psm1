#Requires -Version 7.0
<#
.SYNOPSIS
    Okta management API helpers shared by the PowerShell scripts.

.DESCRIPTION
    The PowerShell counterpart of lib/okta_client.py. Credentials come from
    environment variables:

        OKTA_DOMAIN        https://your-org.okta.com
        OKTA_API_TOKEN     SSWS token (it carries its creator's admin role)

    or, for an OAuth 2.0 service app using private_key_jwt:

        OKTA_CLIENT_ID     client ID of the API Services app
        OKTA_PRIVATE_KEY   path to the PEM private key registered on it
        OKTA_SCOPES        space-separated scopes, e.g. "okta.users.read okta.logs.read"
        OKTA_KEY_ID        optional key ID ("kid")

    OKTA_API_TOKEN wins when both are set. DPoP is not supported.

    Requests retry on 429 (waiting until x-rate-limit-reset, which is a UTC
    epoch time), on 5xx and on network errors. Errors carry the HTTP status in
    $_.Exception.Data['StatusCode'].

.EXAMPLE
    Import-Module "$PSScriptRoot/../lib/OktaClient.psm1"
    $client = New-OktaClient
    Invoke-OktaPagedGet -Client $client -Path '/api/v1/users' | ForEach-Object { $_.profile.login }
#>

$ErrorActionPreference = 'Stop'
$script:UserAgent = 'okta-admin-scripts/0.2'
$script:DefaultMaxPages = 10000
$script:FormulaPrefixes = @('=', '+', '-', '@', "`t", "`r")
# Keep timestamps as the ISO strings Okta sent. PowerShell 7.5 added
# -DateKind; on 7.4 ConvertFrom-Json turns them into local DateTime values.
$script:JsonArgs = @{ NoEnumerate = $true }
if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $script:JsonArgs.DateKind = 'String' }

function New-OktaError {
    param([int]$StatusCode, [string]$Message)
    $ex = [System.Exception]::new($Message)
    $ex.Data['StatusCode'] = $StatusCode
    return $ex
}

function ConvertTo-OktaFilterValue {
    <#
    .SYNOPSIS
        Escape a value for use inside double quotes in an Okta filter expression.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return $Value.Replace('\', '\\').Replace('"', '\"')
}

function Get-OktaRateLimitWait {
    <#
    .SYNOPSIS
        Seconds to wait after a 429. x-rate-limit-reset is an epoch time, so
        the wait is reset minus now, clamped to 1-60 seconds.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param($ResetHeader, [double]$Now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $raw = @($ResetHeader)[0]
    $reset = 0.0
    if (-not [double]::TryParse([string]$raw, [ref]$reset)) { return 5.0 }
    return [Math]::Max(1.0, [Math]::Min($reset - $Now, 60.0))
}

function New-OktaClientAssertion {
    param([string]$ClientId, [string]$TokenUrl, [string]$PrivateKeyPem, [string]$KeyId)
    function ConvertTo-Base64Url([byte[]]$Bytes) {
        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    $header = [ordered]@{ alg = 'RS256'; typ = 'JWT' }
    if ($KeyId) { $header.kid = $KeyId }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $claims = [ordered]@{
        iss = $ClientId; sub = $ClientId; aud = $TokenUrl
        iat = $now; exp = $now + 300; jti = [guid]::NewGuid().ToString('N')
    }
    $enc = [System.Text.Encoding]::UTF8
    $unsigned = (ConvertTo-Base64Url $enc.GetBytes(($header | ConvertTo-Json -Compress))) + '.' +
                (ConvertTo-Base64Url $enc.GetBytes(($claims | ConvertTo-Json -Compress)))
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem($PrivateKeyPem)
        $sig = $rsa.SignData($enc.GetBytes($unsigned),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } finally { $rsa.Dispose() }
    return "$unsigned.$(ConvertTo-Base64Url $sig)"
}

function New-OktaClient {
    <#
    .SYNOPSIS
        Build a client object from the environment (see module help).
    #>
    [CmdletBinding()]
    param()
    if (-not $env:OKTA_DOMAIN) { throw 'Set OKTA_DOMAIN, e.g. https://your-org.okta.com' }
    $domain = $env:OKTA_DOMAIN.Trim().TrimEnd('/')
    if (-not $domain.StartsWith('http')) { $domain = "https://$domain" }
    $client = [pscustomobject]@{
        BaseUrl  = $domain
        AuthMode = $null
        Headers  = @{ 'Accept' = 'application/json'; 'Content-Type' = 'application/json'; 'User-Agent' = $script:UserAgent }
        OAuth    = $null
        TokenExpires = [datetime]::MinValue
    }
    if ($env:OKTA_API_TOKEN) {
        $client.AuthMode = 'ssws'
        $client.Headers['Authorization'] = "SSWS $($env:OKTA_API_TOKEN)"
        return $client
    }
    if ($env:OKTA_CLIENT_ID -and $env:OKTA_PRIVATE_KEY -and $env:OKTA_SCOPES) {
        $pem = $env:OKTA_PRIVATE_KEY
        if (Test-Path -LiteralPath $pem) { $pem = Get-Content -Raw -LiteralPath $pem }
        $client.AuthMode = 'oauth'
        $client.OAuth = @{ ClientId = $env:OKTA_CLIENT_ID; Key = $pem; Scopes = $env:OKTA_SCOPES; KeyId = $env:OKTA_KEY_ID }
        return $client
    }
    throw 'No credentials. Set OKTA_API_TOKEN, or OKTA_CLIENT_ID + OKTA_PRIVATE_KEY + OKTA_SCOPES.'
}

function Update-OktaAccessToken {
    param([Parameter(Mandatory)][psobject]$Client)
    if ($Client.AuthMode -ne 'oauth') { return }
    # Compare without touching TokenExpires: it starts at [datetime]::MinValue, and
    # MinValue.AddSeconds(-60) throws, which broke every first OAuth request.
    if ($Client.TokenExpires -gt [datetime]::UtcNow.AddSeconds(60)) { return }
    $tokenUrl = "$($Client.BaseUrl)/oauth2/v1/token"
    $assertion = New-OktaClientAssertion -ClientId $Client.OAuth.ClientId -TokenUrl $tokenUrl `
        -PrivateKeyPem $Client.OAuth.Key -KeyId $Client.OAuth.KeyId
    $form = @{
        grant_type            = 'client_credentials'
        scope                 = $Client.OAuth.Scopes
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $assertion
    }
    $resp = Invoke-WebRequest -Uri $tokenUrl -Method POST -Body $form `
        -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck
    if ($resp.StatusCode -ne 200) {
        throw (New-OktaError -StatusCode $resp.StatusCode -Message "Token request failed (HTTP $($resp.StatusCode)): $($resp.Content)")
    }
    $tok = $resp.Content | ConvertFrom-Json
    $Client.Headers['Authorization'] = "Bearer $($tok.access_token)"
    $Client.TokenExpires = [datetime]::UtcNow.AddSeconds([int]$tok.expires_in)
}

function Invoke-OktaRequest {
    <#
    .SYNOPSIS
        Send one Okta API request with retries. Returns the parsed body, or
        with -Raw an object with StatusCode, Headers, Body and Uri.
    .PARAMETER Path
        "/api/v1/..." or a full URL (such as a Link rel="next" URL, passed as-is).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query,
        [psobject]$Body,
        [switch]$Raw,
        [int]$Retries = 5
    )
    $uri = if ($Path.StartsWith('http')) { $Path } else { $Client.BaseUrl + $Path }
    if ($Query -and $Query.Count) {
        $qs = ($Query.GetEnumerator() | Sort-Object Key | ForEach-Object {
            "$([uri]::EscapeDataString($_.Key))=$([uri]::EscapeDataString([string]$_.Value))"
        }) -join '&'
        $uri = "$uri`?$qs"
    }
    $params = @{ Uri = $uri; Method = $Method; TimeoutSec = 30; SkipHttpErrorCheck = $true }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress) }

    $lastError = $null
    for ($i = 0; $i -lt $Retries; $i++) {
        Update-OktaAccessToken -Client $Client
        $params.Headers = $Client.Headers
        try {
            $resp = Invoke-WebRequest @params
        } catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds ([Math]::Min([Math]::Pow(2, $i), 30))
            continue
        }
        $code = [int]$resp.StatusCode
        if ($code -eq 429) {
            Start-Sleep -Seconds (Get-OktaRateLimitWait -ResetHeader $resp.Headers['x-rate-limit-reset'])
            $lastError = 'HTTP 429'
            continue
        }
        if ($code -ge 500) {
            Start-Sleep -Seconds ([Math]::Min([Math]::Pow(2, $i), 30))
            $lastError = "HTTP $code"
            continue
        }
        if ($code -eq 401) { throw (New-OktaError 401 "Okta rejected the credentials (HTTP 401) on $Method $Path.") }
        if ($code -eq 403) { throw (New-OktaError 403 "HTTP 403 on $Method $Path : the credentials lack permission for this call. $($resp.Content)") }
        if ($code -ge 400) { throw (New-OktaError $code "HTTP $code on $Method $Path : $($resp.Content)") }

        $bodyObj = $null
        if ($resp.Content) { $bodyObj = $resp.Content | ConvertFrom-Json @script:JsonArgs }
        if ($Raw) {
            return [pscustomobject]@{ StatusCode = $code; Headers = $resp.Headers; Body = $bodyObj; Uri = $uri }
        }
        return $bodyObj
    }
    throw (New-OktaError 0 "Gave up on $Method $Path after $Retries attempts: $lastError")
}

function Get-OktaNextLink {
    param($Headers)
    foreach ($line in @($Headers['Link'])) {
        foreach ($part in ([string]$line -split ',')) {
            if ($part -match '<([^>]+)>\s*;\s*rel="next"') { return $Matches[1] }
        }
    }
    return $null
}

function Invoke-OktaPagedGet {
    <#
    .SYNOPSIS
        Stream items across pages, following Link rel="next" verbatim.
        Stops at the last page, on an empty page (System Log polling always
        sends a next link), or with an error after -MaxPages pages.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query,
        [int]$MaxPages = $script:DefaultMaxPages
    )
    $q = @{}
    if ($Query) { foreach ($k in $Query.Keys) { $q[$k] = $Query[$k] } }
    if (-not $q.ContainsKey('limit')) { $q['limit'] = 200 }
    $resp = Invoke-OktaRequest -Client $Client -Method GET -Path $Path -Query $q -Raw
    $pages = 1
    while ($true) {
        $items = @()
        if ($null -ne $resp.Body) {
            if ($resp.Body -is [array]) { $items = $resp.Body }
            elseif ($resp.Body.PSObject.Properties['value']) { $items = @($resp.Body.value) }
            else { $items = @($resp.Body) }
        }
        foreach ($item in $items) { Write-Output $item }
        $next = Get-OktaNextLink -Headers $resp.Headers
        if (-not $next -or $items.Count -eq 0) { return }
        if ($pages -ge $MaxPages) { throw "Stopped paging $Path after $MaxPages pages." }
        $resp = Invoke-OktaRequest -Client $Client -Method GET -Path $next -Raw
        $pages++
    }
}

function Get-OktaUtcNow {
    [OutputType([string])]
    param()
    return [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Get-OktaLogs {
    <#
    .SYNOPSIS
        Bounded System Log read between -Since and -Until (default: now).
        With both bounds Okta returns a finite set of pages.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [string]$Filter,
        [string]$Since,
        [string]$Until = (Get-OktaUtcNow)
    )
    $q = @{ sortOrder = 'ASCENDING'; limit = 1000; until = $Until }
    if ($Filter) { $q['filter'] = $Filter }
    if ($Since) { $q['since'] = $Since }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/logs' -Query $q
}

function Get-OktaLogPoll {
    <#
    .SYNOPSIS
        One System Log polling pass for watch modes. Pass -Cursor $null the
        first time, then the Cursor this returns. Reads until an empty page.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [AllowNull()][string]$Cursor,
        [string]$Filter,
        [string]$Since
    )
    if ($Cursor) {
        $resp = Invoke-OktaRequest -Client $Client -Method GET -Path $Cursor -Raw
    } else {
        $q = @{ sortOrder = 'ASCENDING'; limit = 1000 }
        if ($Filter) { $q['filter'] = $Filter }
        if ($Since) { $q['since'] = $Since }
        $resp = Invoke-OktaRequest -Client $Client -Method GET -Path '/api/v1/logs' -Query $q -Raw
    }
    $events = [System.Collections.Generic.List[object]]::new()
    $current = $resp.Uri
    for ($i = 0; $i -lt $script:DefaultMaxPages; $i++) {
        $page = @()
        if ($null -ne $resp.Body) { $page = @($resp.Body) }
        foreach ($e in $page) { $events.Add($e) }
        $next = Get-OktaNextLink -Headers $resp.Headers
        if ($page.Count -eq 0 -or -not $next) {
            if (-not $next) { $next = $current }
            return [pscustomobject]@{ Events = $events.ToArray(); Cursor = $next }
        }
        $current = $next
        $resp = Invoke-OktaRequest -Client $Client -Method GET -Path $next -Raw
    }
    throw 'System Log polling did not catch up.'
}

function Get-OktaUsers {
    <#
    .SYNOPSIS
        List users with any of the given statuses (default ACTIVE). Pass an
        empty -Status to list every user.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [string[]]$Status = @('ACTIVE'))
    $q = @{}
    $s = @($Status | Where-Object { $_ })
    if ($s.Count) { $q['filter'] = ($s | ForEach-Object { "status eq `"$(ConvertTo-OktaFilterValue $_)`"" }) -join ' or ' }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/users' -Query $q
}

function Get-OktaUserByLogin {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$Login)
    $q = @{ filter = "profile.login eq `"$(ConvertTo-OktaFilterValue $Login)`""; limit = 2 }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/users' -Query $q | Select-Object -First 1
}

function Get-OktaCurrentUser {
    <#
    .SYNOPSIS
        The user the SSWS token belongs to (GET /api/v1/users/me); $null in OAuth mode.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client)
    if ($Client.AuthMode -ne 'ssws') { return $null }
    Invoke-OktaRequest -Client $Client -Method GET -Path '/api/v1/users/me'
}

function Get-OktaRoleAssigneeUserIds {
    <#
    .SYNOPSIS
        IDs of every user with an admin role, direct or via a group
        (GET /api/v1/iam/assignees/users, which wraps results in "value").
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client)
    $path = '/api/v1/iam/assignees/users?limit=100'
    for ($i = 0; $path -and $i -lt $script:DefaultMaxPages; $i++) {
        $body = Invoke-OktaRequest -Client $Client -Method GET -Path $path
        $vals = @($body.value)
        foreach ($u in $vals) { if ($u.id) { Write-Output ([string]$u.id) } }
        $path = $null
        if ($vals.Count -and $body._links -and $body._links.next) { $path = [string]$body._links.next.href }
    }
}

function Get-OktaFactors {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$UserId)
    Invoke-OktaPagedGet -Client $Client -Path "/api/v1/users/$UserId/factors"
}

function Get-OktaPolicies {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$Type)
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/policies' -Query @{ type = $Type }
}

function Get-OktaPolicyRules {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$PolicyId)
    Invoke-OktaPagedGet -Client $Client -Path "/api/v1/policies/$PolicyId/rules"
}

function Get-OktaZones {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client)
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/zones'
}

function Get-OktaApps {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client)
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/apps'
}

function Get-OktaAppUsers {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$AppId)
    Invoke-OktaPagedGet -Client $Client -Path "/api/v1/apps/$AppId/users"
}

function Get-OktaGroups {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [string]$Query)
    $q = @{}
    if ($Query) { $q['q'] = $Query }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/groups' -Query $q
}

function Get-OktaUserRoles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$UserId)
    Invoke-OktaPagedGet -Client $Client -Path "/api/v1/users/$UserId/roles"
}

function Get-OktaGroupRoles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$GroupId)
    Invoke-OktaPagedGet -Client $Client -Path "/api/v1/groups/$GroupId/roles"
}

function Get-OktaAuthServers {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client)
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/authorizationServers'
}

function ConvertTo-OktaUtcDate {
    <#
    .SYNOPSIS
        Turn an Okta timestamp into a UTC DateTime. Accepts the ISO string or
        the DateTime that ConvertFrom-Json produces on PowerShell 7.4.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([AllowNull()]$Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    return [datetimeoffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture).UtcDateTime
}

function ConvertTo-OktaIsoString {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    $d = ConvertTo-OktaUtcDate $Value
    if ($null -eq $d) { return '' }
    return $d.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function ConvertTo-CsvSafeValue {
    <#
    .SYNOPSIS
        Prefix a quote to values a spreadsheet would read as a formula
        (= + - @ tab CR). Okta profile fields are often user-editable.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { $Value = (@($Value) -join '; ') }
    if ($Value -is [string] -and $Value.Length -gt 0 -and ([string]$Value[0]) -in $script:FormulaPrefixes) {
        return "'" + $Value
    }
    return $Value
}

function Export-OktaCsv {
    <#
    .SYNOPSIS
        Export-Csv with formula-injection protection on every cell.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][psobject]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Append
    )
    begin { $rows = [System.Collections.Generic.List[object]]::new() }
    process {
        $safe = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $safe[$p.Name] = ConvertTo-CsvSafeValue $p.Value }
        $rows.Add([pscustomobject]$safe)
    }
    end {
        if ($rows.Count -eq 0) { return }
        $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8 -Append:$Append
    }
}

Export-ModuleMember -Function `
    New-OktaClient, Invoke-OktaRequest, Invoke-OktaPagedGet, Get-OktaUtcNow, `
    ConvertTo-OktaFilterValue, Get-OktaRateLimitWait, New-OktaClientAssertion, `
    Get-OktaUsers, Get-OktaUserByLogin, Get-OktaCurrentUser, Get-OktaRoleAssigneeUserIds, `
    Get-OktaFactors, Get-OktaLogs, Get-OktaLogPoll, Get-OktaPolicies, Get-OktaPolicyRules, `
    Get-OktaZones, Get-OktaApps, Get-OktaAppUsers, Get-OktaGroups, Get-OktaUserRoles, `
    Get-OktaGroupRoles, Get-OktaAuthServers, ConvertTo-CsvSafeValue, Export-OktaCsv, `
    ConvertTo-OktaUtcDate, ConvertTo-OktaIsoString
