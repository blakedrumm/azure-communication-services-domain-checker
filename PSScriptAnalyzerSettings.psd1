@{
    # ===========================================================================
    # PSScriptAnalyzer configuration for the ACS Email Domain Checker
    # ===========================================================================
    # This project is a single-file PowerShell app assembled from the numbered
    # src/*.ps1 fragments by Build-Release.ps1. A handful of default rules either
    # flag deliberate design decisions or produce false positives against that
    # build model. They are excluded below -- each with a rationale -- so a full
    # analyzer run (and the VS Code Problems panel, which auto-detects this file
    # at the workspace root) comes back clean WITHOUT hiding real defects.
    #
    # Rules that catch genuine bugs are intentionally LEFT ENABLED, e.g.
    # PSUseApprovedVerbs, PSPossibleIncorrectComparisonWithNull, and
    # PSAvoidAssignmentToAutomaticVariable. Do NOT add those here.
    #
    # Manual usage (mirrors what the PowerShell extension does automatically):
    #   Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    # ===========================================================================

    # Only Warning and Error findings are treated as actionable -- this matches
    # what the VS Code Problems panel surfaces. Information-level style rules
    # (e.g. PSUseOutputTypeCorrectly) are advisory and not enforced here.
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Empty catch blocks are used deliberately for best-effort, non-critical
        # operations (telemetry, header stamping, resource cleanup) that must
        # never break the request/response path if they fail.
        'PSAvoidUsingEmptyCatchBlock',

        # Several helpers use plural nouns (Get-ParentDomains, Get-SpfTokens,
        # Get-MxRecordObjects, ...). Renaming is purely cosmetic and would
        # cascade to every call site plus the runspace registration list.
        'PSUseSingularNouns',

        # $global: scope is used on purpose to share state (metrics store, rate-
        # limit buckets) across the worker runspaces that service HTTP requests.
        'PSAvoidGlobalVars',

        # The "state-changing" functions here are internal helpers, not cmdlets
        # a user invokes interactively, so -WhatIf/-Confirm plumbing adds no
        # value and would only complicate the call sites.
        'PSUseShouldProcessForStateChangingFunctions',

        # Individual src/*.ps1 fragments are authored without a BOM; the build
        # (Build-Release.ps1) writes the final acs-domain-checker.ps1 as UTF-8
        # WITH a BOM, so per-fragment BOMs are irrelevant to the shipped file.
        'PSUseBOMForUnicodeEncodedFile',

        # False positives from the single-file build: variables are frequently
        # assigned in one fragment and consumed in a later concatenated fragment,
        # which the per-file analyzer cannot see.
        'PSUseDeclaredVarsMoreThanAssignments',

        # Parameters are sometimes present for signature/interface consistency
        # (event-handler delegates, shared handler shapes) without being read.
        'PSReviewUnusedParameter',

        # A single internal helper is flagged for a process block; it is not used
        # as a pipeline cmdlet.
        'PSUseProcessBlockForPipelineCommand'
    )
}
