<#
    .SYNOPSIS
        Enables a Windows optional feature.

    .DESCRIPTION
        Enables the Windows optional feature with the specified name and outputs
        a log to the specified path.

    .PARAMETER Name
        The name of the Windows optional feature to enable.

    .PARAMETER LogPath
        The path to the file to log the enable operation to.

    .NOTES
        Can only be run on Windows client operating systems.
        The DISM PowerShell module must be available on the target machine.
#>
Configuration WindowsOptionalFeatureConfig
{
    <#param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name
    )#>

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node WindowsOptionalFeatureConfig
    {
        WindowsOptionalFeature 'EnableOptionalFeature'
        {
            Name    = 'TelnetClient'
            Ensure = 'Enable'
            LogPath = "$env:HOMEDRIVE\WindowsOptionalFeatures"
        }
    }
}
WindowsOptionalFeatureConfig