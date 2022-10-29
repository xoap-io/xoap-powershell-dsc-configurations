<#
This example adds a new Teams PSTN Usage.
#>

Configuration Example
{
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]
        $credsGlobalAdmin
    )
    Import-DscResource -ModuleName Microsoft365DSC

    node localhost
    {
        TeamsPstnUsage 'ConfigurePstnUsage'
        {
            Usage      = 'Long Distance'
            Ensure     = 'Present'
            Credential = $credsGlobalAdmin
        }
    }
}
