Configuration windows-optional-feature-config
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node windows-optional-feature-config
    {
        WindowsOptionalFeature 'EnableOptionalFeature'
        {
            Name    = 'TelnetClient'
            Ensure = 'Enable'
            LogPath = "$env:HOMEDRIVE\windows-optional-feature-config"
        }
    }
}
windows-optional-feature-config
