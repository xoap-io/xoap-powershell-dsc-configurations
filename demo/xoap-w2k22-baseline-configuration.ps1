Configuration 'w2k22-baseline-configuration'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'XOAPBaselineModuleDSC'

    Node $AllNodes.NodeName
    {
        WindowsOptionalFeature "NET-Framework-Features"
        {
            Name    = "NET-Framework-Features"
            Ensure  = "Enable"
        }

        WindowsOptionalFeature "GPMC"
        {
            Name    = "GPMC"
            Ensure  = "Enable"
        }
        
        File "DemoDirectory"
        {
            Type = 'Directory'
            Ensure = 'Present'
            DestinationPath = "C:\DemoDirectory"
        }
    }
}