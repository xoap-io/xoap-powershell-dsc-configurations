Configuration Windows_Optional_Feature
{
Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '8.5.0'
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node Windows_Optional_Feature
    {
        WindowsOptionalFeature 'EnableOptionalFeature'
        {
            Name    = 'TelnetClient'
            Ensure = 'Enable'
            LogPath = "$env:HOMEDRIVE\WindowsOptionalFeatures"
        }
    }
}
Windows_Optional_Feature