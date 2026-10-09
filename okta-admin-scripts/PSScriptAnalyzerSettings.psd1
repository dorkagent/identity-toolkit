# PSScriptAnalyzer settings for these scripts.
# Run: Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
@{
    Severity     = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        # Get-OktaUsers, Get-OktaApps etc. mirror the Python client's list_*
        # helpers; plural nouns read better here than the convention.
        'PSUseSingularNouns',
        # New-OktaClient and the small row/finding builders only create
        # in-memory objects. Scripts that change Okta use an explicit -Apply.
        'PSUseShouldProcessForStateChangingFunctions',
        # Tenant-DriftDetector's -List switch selects a parameter set and is
        # never read directly.
        'PSReviewUnusedParameter',
        # Internal helpers in the scripts are called positionally on purpose to
        # keep the call sites short; exported module functions use named
        # parameters in their examples.
        'PSAvoidUsingPositionalParameters',
        # Module-internal helpers are documented inline; every script and
        # exported function has comment-based help.
        'PSProvideCommentHelp'
    )
}
