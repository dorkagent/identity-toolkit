# PSScriptAnalyzer settings for the dorkagent/Okta script suite.
# Run: Invoke-ScriptAnalyzer -Path scripts/ -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
@{
    Severity     = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        # Internal Get-* helpers intentionally use plural nouns to mirror the
        # Python client's list_* wrappers (Get-OktaUsers etc.). They are not
        # exported cmdlets, so the singular-noun convention does not apply.
        'PSUseSingularNouns',
        # New-OktaClient / New-BreakGlassRow only construct in-memory objects;
        # they change no system state. ShouldProcess would be noise.
        'PSUseShouldProcessForStateChangingFunctions',
        # Tenant-DriftDetector's -List switch is parameter-set-driven (it is the
        # default parameter set); it is intentionally never referenced in code.
        'PSReviewUnusedParameter',
        # Information-severity noise for internal module helpers; the public
        # scripts all carry full comment-based help.
        'PSProvideCommentHelp'
    )
}
