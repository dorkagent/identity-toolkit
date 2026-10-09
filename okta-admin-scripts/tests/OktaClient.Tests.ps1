#Requires -Version 7.0
# Pester 5 tests for lib/OktaClient.psm1. HTTP is mocked; nothing leaves the machine.

BeforeAll {
    Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
    $env:OKTA_DOMAIN = 'https://example.okta.com'
    $env:OKTA_API_TOKEN = 'test-token'
    Remove-Item Env:OKTA_CLIENT_ID -ErrorAction SilentlyContinue

    function New-FakeResponse {
        param([int]$Status = 200, $Body = @(), [string]$Next)
        $headers = @{}
        if ($Next) { $headers['Link'] = @("<$Next>; rel=`"next`"") }
        [pscustomobject]@{ StatusCode = $Status; Headers = $headers; Content = (ConvertTo-Json -InputObject $Body -Depth 5 -Compress) }
    }
}

Describe 'ConvertTo-CsvSafeValue' {
    It 'prefixes formula characters' {
        foreach ($v in '=1+1', '+1', '-1', '@SUM(A1)') { ConvertTo-CsvSafeValue $v | Should -Be "'$v" }
    }
    It 'leaves normal values alone' {
        ConvertTo-CsvSafeValue 'alice@example.com' | Should -Be 'alice@example.com'
        ConvertTo-CsvSafeValue 5 | Should -Be 5
    }
}

Describe 'Export-OktaCsv' {
    It 'writes neutralised cells' {
        $path = Join-Path $TestDrive 'out.csv'
        [pscustomobject]@{ Name = '=HYPERLINK("x")'; Login = 'bob' } | Export-OktaCsv -Path $path
        (Import-Csv $path).Name | Should -Be "'=HYPERLINK(`"x`")"
    }
}

Describe 'Get-OktaRateLimitWait' {
    It 'treats x-rate-limit-reset as an epoch time' {
        Get-OktaRateLimitWait -ResetHeader @('1000030') -Now 1000000 | Should -Be 30
        Get-OktaRateLimitWait -ResetHeader @('999990') -Now 1000000 | Should -Be 1
        Get-OktaRateLimitWait -ResetHeader @('2000000') -Now 1000000 | Should -Be 60
        Get-OktaRateLimitWait -ResetHeader $null | Should -Be 5
    }
}

Describe 'ConvertTo-OktaFilterValue' {
    It 'escapes quotes and backslashes' {
        ConvertTo-OktaFilterValue 'a"b\c' | Should -Be 'a\"b\\c'
    }
}

Describe 'Invoke-OktaPagedGet' {
    It 'stops on an empty page even when a next link is present' {
        $script:n = 0
        Mock -ModuleName OktaClient Invoke-WebRequest {
            $script:n++
            if ($script:n -eq 1) { New-FakeResponse -Body @(@{ id = 'e1' }) -Next 'https://example.okta.com/api/v1/logs?after=1' }
            else { New-FakeResponse -Body @() -Next 'https://example.okta.com/api/v1/logs?after=2' }
        }
        $client = New-OktaClient
        $items = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/logs')
        $items.Count | Should -Be 1
        Should -Invoke -ModuleName OktaClient Invoke-WebRequest -Times 2 -Exactly
    }

    It 'passes the next link through verbatim' {
        $script:uris = @()
        Mock -ModuleName OktaClient Invoke-WebRequest {
            $script:uris += $Uri
            if ($script:uris.Count -eq 1) { New-FakeResponse -Body @(@{ id = 1 }) -Next 'https://example.okta.com/api/v1/users?after=abc%2Bdef&limit=200' }
            else { New-FakeResponse -Body @(@{ id = 2 }) }
        }
        $ids = @(Invoke-OktaPagedGet -Client (New-OktaClient) -Path '/api/v1/users' | ForEach-Object id)
        $ids | Should -Be @(1, 2)
        $script:uris[1] | Should -Be 'https://example.okta.com/api/v1/users?after=abc%2Bdef&limit=200'
    }
}

Describe 'Get-OktaLogs' {
    It 'sends a bounded query with until' {
        Mock -ModuleName OktaClient Invoke-WebRequest { $script:lastUri = $Uri; New-FakeResponse -Body @() }
        @(Get-OktaLogs -Client (New-OktaClient) -Filter 'eventType eq "x"' -Since '2026-01-01T00:00:00.000Z').Count | Should -Be 0
        $script:lastUri | Should -Match 'until='
        $script:lastUri | Should -Match 'sortOrder=ASCENDING'
    }
}

Describe 'Invoke-OktaRequest errors' {
    It 'tags errors with the HTTP status' {
        Mock -ModuleName OktaClient Invoke-WebRequest { New-FakeResponse -Status 403 -Body @{ errorSummary = 'no' } }
        $err = $null
        try { Invoke-OktaRequest -Client (New-OktaClient) -Method GET -Path '/api/v1/api-tokens' } catch { $err = $_ }
        $err.Exception.Data['StatusCode'] | Should -Be 403
        $err.Exception.Message | Should -Not -Match 'rejected the credentials'
    }

    It 'retries a 429 and then succeeds' {
        $script:n = 0
        Mock -ModuleName OktaClient Start-Sleep {}
        Mock -ModuleName OktaClient Invoke-WebRequest {
            $script:n++
            if ($script:n -eq 1) {
                [pscustomobject]@{ StatusCode = 429; Headers = @{ 'x-rate-limit-reset' = @([string]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3)) }; Content = '{}' }
            } else { New-FakeResponse -Body @{ id = 'ok' } }
        }
        (Invoke-OktaRequest -Client (New-OktaClient) -Method GET -Path '/api/v1/users/me').id | Should -Be 'ok'
        Should -Invoke -ModuleName OktaClient Start-Sleep -Times 1 -Exactly
    }
}

Describe 'OAuth client assertion' {
    It 'builds an RS256 JWT with the documented claims' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $pem = $rsa.ExportPkcs8PrivateKeyPem()
        $jwt = New-OktaClientAssertion -ClientId '0oaX' -TokenUrl 'https://example.okta.com/oauth2/v1/token' -PrivateKeyPem $pem -KeyId 'k1'
        $parts = $jwt.Split('.')
        $parts.Count | Should -Be 3
        function ConvertFrom-B64UrlBytes([string]$s) {
            $s = $s.Replace('-', '+').Replace('_', '/'); while ($s.Length % 4) { $s += '=' }
            , [Convert]::FromBase64String($s)
        }
        function ConvertFrom-B64Url([string]$s) { [Text.Encoding]::UTF8.GetString((ConvertFrom-B64UrlBytes $s)) }
        $claims = ConvertFrom-B64Url $parts[1] | ConvertFrom-Json
        $claims.iss | Should -Be '0oaX'
        $claims.sub | Should -Be '0oaX'
        $claims.aud | Should -Be 'https://example.okta.com/oauth2/v1/token'
        ($claims.exp - $claims.iat) | Should -BeLessOrEqual 3600
        (ConvertFrom-B64Url $parts[0] | ConvertFrom-Json).kid | Should -Be 'k1'
        $sig = ConvertFrom-B64UrlBytes $parts[2]
        $ok = $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"), $sig,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $ok | Should -BeTrue
    }
}

Describe 'OAuth token fetch' {
    BeforeEach {
        $script:savedToken = $env:OKTA_API_TOKEN
        Remove-Item Env:OKTA_API_TOKEN -ErrorAction SilentlyContinue
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $env:OKTA_CLIENT_ID = '0oaX'
        $env:OKTA_PRIVATE_KEY = $rsa.ExportPkcs8PrivateKeyPem()
        $env:OKTA_SCOPES = 'okta.users.read'
        $script:tokenCalls = 0
        Mock -ModuleName OktaClient Invoke-WebRequest {
            if ($Uri -like '*/oauth2/v1/token') {
                $script:tokenCalls++
                return [pscustomobject]@{ StatusCode = 200; Headers = @{}; Content = '{"access_token":"at1","expires_in":3600}' }
            }
            [pscustomobject]@{ StatusCode = 200; Headers = @{}; Content = (ConvertTo-Json @{ auth = $Headers['Authorization'] } -Compress) }
        }
    }
    AfterEach {
        $env:OKTA_API_TOKEN = $script:savedToken
        Remove-Item Env:OKTA_CLIENT_ID, Env:OKTA_PRIVATE_KEY, Env:OKTA_SCOPES -ErrorAction SilentlyContinue
    }
    It 'fetches a token on the first request of a new client and reuses it' {
        $c = New-OktaClient
        $c.AuthMode | Should -Be 'oauth'
        (Invoke-OktaRequest -Client $c -Method GET -Path '/api/v1/users/x').auth | Should -Be 'Bearer at1'
        $null = Invoke-OktaRequest -Client $c -Method GET -Path '/api/v1/users/y'
        $script:tokenCalls | Should -Be 1
    }
}
