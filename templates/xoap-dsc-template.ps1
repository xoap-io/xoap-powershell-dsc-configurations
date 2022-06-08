Configuration CONFIGURATIONNAME
{
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node CONFIGURATIONNAME
    {
        WindowsOptionalFeature "Microsoft-Hyper-V-All"
        {
            Name    = "Microsoft-Hyper-V-All"
            Ensure  = "Disable"
        }
        
        File "DemoDirectory"
        {
            Type = 'Directory'
            Ensure = 'Present'
            DestinationPath = "C:\DemoDirectory"
        }
    }
}
CONFIGURATIONNAME
