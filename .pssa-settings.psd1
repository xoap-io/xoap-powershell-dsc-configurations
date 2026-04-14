@{
    Severity     = @('Warning', 'Error')

    ExcludeRules = @(
        # DSC Configuration blocks change state by design - ShouldProcess not applicable
        'PSUseShouldProcessForStateChangingFunctions',

        # Helper scripts legitimately use Write-Host for console output to users
        'PSAvoidUsingWriteHost',

        # Pre-commit hooks handle trailing whitespace; avoid duplicate enforcement
        'PSAvoidTrailingWhitespace',

        # DSC resource property names use PascalCase by convention (e.g. ValueName, ValueData)
        'PSUsePSCredentialType'
    )
}
