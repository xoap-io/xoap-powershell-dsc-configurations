Configuration 'xoap-w2k16-baseline'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'XOAPBaselineModuleDSC'
    Import-DscResource -ModuleName "cShortcut"

    Node "xoap-w2k16-baseline"
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
    }
}