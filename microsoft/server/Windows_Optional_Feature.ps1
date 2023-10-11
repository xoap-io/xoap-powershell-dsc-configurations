Configuration 'Windows_Optional_Feature'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'Windows_Optional_Feature'
    {
        WindowsOptionalFeature 'EnableOptionalFeature'
        {
            Name    = 'TelnetClient'
            Ensure = 'Enable'
            LogPath = "$env:HOMEDRIVE\WindowsOptionalFeatures"
        }
    }
}
