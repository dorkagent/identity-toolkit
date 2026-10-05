<#
.SYNOPSIS
    Shared Okta API client module.

.DESCRIPTION
    Mirrors lib/okta_client.py. Auth comes from environment variables only --
    never hardcode a token:

        OKTA_DOMAIN      e.g. https://dev-123456.okta.com
        OKTA_API_TOKEN   an SSWS API token (read-only is enough for auditors)

    Handles Link-header pagination and honors 429 rate-limit responses via
    the x-rate-limit-reset header.

.EXAMPLE
    Import-Module "$PSScriptRoot/../../lib/OktaClient.psm1"
    $client = New-OktaClient
    Invoke-OktaPagedGet -Client $client -Path "/api/v1/users" |
        ForEach-Object { $_.profile.login }
#>

$ErrorActionPreference = 'Stop'

function Assert-OktaConfig {
    <#
    .SYNOPSIS
        Fail loudly when OKTA_DOMAIN / OKTA_API_TOKEN are missing.
    #>
    if (-not $env:OKTA_DOMAIN -or -not $env:OKTA_API_TOKEN) {
        throw "Set OKTA_DOMAIN (e.g. https://dev-123456.okta.com) and OKTA_API_TOKEN environment variables."
    }
}

function New-OktaClient {
    <#
    .SYNOPSIS
        Build a client object carrying the base URL and auth headers.
    #>
    [CmdletBinding()]
    param()
    Assert-OktaConfig
    $domain = $env:OKTA_DOMAIN.TrimEnd('/')
    if (-not $domain.StartsWith('http')) { $domain = "https://$domain" }
    return [pscustomobject]@{
        BaseUrl = $domain
        Headers = @{
            'Authorization' = "SSWS $($env:OKTA_API_TOKEN)"
            'Accept'        = 'application/json'
            'Content-Type'  = 'application/json'
            'User-Agent'    = 'okta-ideas/0.1'
        }
    }
}

function Invoke-OktaRequest {
    <#
    .SYNOPSIS
        Issue one Okta API request, honoring 429 with x-rate-limit-reset.
    .PARAMETER Client
        Object returned by New-OktaClient.
    .PARAMETER Method
        HTTP method (GET, POST, PUT, DELETE).
    .PARAMETER Path
        API path, e.g. "/api/v1/users".
    .PARAMETER Query
        Hashtable of query-string parameters.
    .PARAMETER Body
        Object serialized as the JSON request body.
    .PARAMETER Raw
        Return the full response (headers + parsed body) instead of just the body.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query,
        [psobject]$Body,
        [switch]$Raw
    )
    $uri = $Client.BaseUrl + $Path
    if ($Query -and $Query.Count) {
        $qs = ($Query.GetEnumerator() | ForEach-Object {
            "$([uri]::EscapeDataString($_.Key))=$([uri]::EscapeDataString([string]$_.Value))"
        }) -join '&'
        $uri = "$uri`?$qs"
    }
    $params = @{
        Uri     = $uri
        Method  = $Method
        Headers = $Client.Headers
        TimeoutSec = 30
    }
    if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 20) }

    $retries = 5
    for ($i = 0; $i -lt $retries; $i++) {
        try {
            $resp = Invoke-WebRequest @params -SkipHttpErrorCheck
        } catch {
            throw "Okta request failed: $($_.Exception.Message)"
        }
        if ($resp.StatusCode -eq 429) {
            $wait = 5
            $reset = $resp.Headers['x-rate-limit-reset']
            if ($reset -and ($reset -as [int])) { $wait = [int]$reset }
            $wait = [Math]::Max(1, [Math]::Min($wait, 60)) + 1
            Start-Sleep -Seconds $wait
            continue
        }
        if ($resp.StatusCode -in 401, 403) {
            throw "Okta rejected the API token (HTTP $($resp.StatusCode)). Check OKTA_API_TOKEN and its permissions."
        }
        if ($resp.StatusCode -ge 400) {
            throw "Okta API error $($resp.StatusCode) on $Method $Path : $($resp.Content)"
        }
        if ($Raw) {
            $bodyObj = $null
            if ($resp.Content) { $bodyObj = $resp.Content | ConvertFrom-Json -ErrorAction SilentlyContinue }
            return [pscustomobject]@{ StatusCode = $resp.StatusCode; Headers = $resp.Headers; Body = $bodyObj }
        }
        if ($resp.Content) { return ($resp.Content | ConvertFrom-Json) }
        return $null
    }
    throw "Okta rate limit persisted after retries; try again later."
}

function Invoke-OktaPagedGet {
    <#
    .SYNOPSIS
        Stream items across all pages (Okta `after` cursor via Link header).
    .PARAMETER Client
        Object returned by New-OktaClient.
    .PARAMETER Path
        API path, e.g. "/api/v1/users".
    .PARAMETER Query
        Hashtable of query-string parameters (limit defaults to 200).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query
    )
    $q = @{}
    if ($Query) { foreach ($k in $Query.Keys) { $q[$k] = $Query[$k] } }
    if (-not $q.ContainsKey('limit')) { $q['limit'] = 200 }
    $nextUrl = $null
    $first = $true
    do {
        if ($first) {
            $resp = Invoke-OktaRequest -Client $Client -Method GET -Path $Path -Query $q -Raw
            $first = $false
        } else {
            $uri = [uri]$nextUrl
            $q2 = @{}
            foreach ($pair in ($uri.Query.TrimStart('?') -split '&')) {
                if ($pair) { $kv = $pair -split '=', 2; $q2[[uri]::UnescapeDataString($kv[0])] = [uri]::UnescapeDataString($kv[1]) }
            }
            $resp = Invoke-OktaRequest -Client $Client -Method GET -Path $uri.AbsolutePath -Query $q2 -Raw
        }
        if ($resp.Body) {
            if ($resp.Body -is [System.Collections.IEnumerable] -and $resp.Body -isnot [string]) {
                foreach ($item in $resp.Body) { Write-Output $item }
            } else {
                Write-Output $resp.Body
            }
        }
        $nextUrl = $null
        $link = $resp.Headers['Link']
        if ($link) {
            foreach ($part in ($link -split ',')) {
                if ($part -match '<([^>]+)>\s*;\s*rel="next"') { $nextUrl = $Matches[1] }
            }
        }
    } while ($nextUrl)
}

function Get-OktaUsers {
    <#
    .SYNOPSIS List users, optionally filtered by status.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [string]$Status = 'ACTIVE')
    $q = @{}
    if ($Status) { $q['filter'] = "status eq `"$Status`"" }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/users' -Query $q
}

function Get-OktaUserByLogin {
    <#
    .SYNOPSIS Return the first user with the given login, or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$Login)
    $q = @{ filter = "profile.login eq `"$Login`""; limit = 2 }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/users' -Query $q | Select-Object -First 1
}

function Get-OktaFactors {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Client, [Parameter(Mandatory)][string]$UserId)
    Invoke-OktaPagedGet -Client $Client -Path "/api/v1/users/$UserId/factors"
}

function Get-OktaLogs {
    <#
    .SYNOPSIS Stream System Log events. -Since is an ISO8601 UTC timestamp.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$Client,
        [string]$Filter,
        [string]$Since
    )
    $q = @{ sortOrder = 'ASCENDING' }
    if ($Filter) { $q['filter'] = $Filter }
    if ($Since)  { $q['since'] = $Since }
    Invoke-OktaPagedGet -Client $Client -Path '/api/v1/logs' -Query $q
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

Export-ModuleMember -Function `
    Assert-OktaConfig, New-OktaClient, Invoke-OktaRequest, Invoke-OktaPagedGet, `
    Get-OktaUsers, Get-OktaUserByLogin, Get-OktaFactors, Get-OktaLogs, `
    Get-OktaPolicies, Get-OktaPolicyRules, Get-OktaZones, Get-OktaApps, `
    Get-OktaAppUsers, Get-OktaGroups, Get-OktaUserRoles, Get-OktaGroupRoles, `
    Get-OktaAuthServers
