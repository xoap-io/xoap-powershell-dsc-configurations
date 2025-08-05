
# DSC Configuration: Windows_Optional_Feature
# Purpose: Enables the Telnet Client optional Windows feature and logs the operation.
Configuration 'Windows_Optional_Feature'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'Windows_Optional_Feature'
    {
        # Enables the Telnet Client feature
        WindowsOptionalFeature 'TelnetClient_Enable'
        {
            Name    = 'TelnetClient'
            Ensure  = 'Enable'
            LogPath = "$env:HOMEDRIVE\WindowsOptionalFeatures"
        }
    }
}
