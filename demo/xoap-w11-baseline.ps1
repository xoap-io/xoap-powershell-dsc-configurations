Configuration 'xoap-w11-baseline'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'XOAPBaselineModuleDSC'
    Import-DscResource -ModuleName "cShortcut"

    Node "xoap-w11-baseline"
    {
        Registry "DemoRegistry"
        {
            Key = "HKEY_LOCAL_MACHINE\Software\XOAP\DemoKey"
            Ensure = "Present"
            ValueName = "DemoKey"
            ValueType = "String"
            ValueData = "This is a Demo Test Registry"
        }

        File "DemoFile"
        {
            Ensure = "Present"
            DestinationPath = "C:\XOAP\Demo.txt"
            Contents = "This is a text document"
        }

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
            DestinationPath = "C:\XOAP\DemoDirectory"
            DependsOn = "[File]DemoFile"
        }
    }
}