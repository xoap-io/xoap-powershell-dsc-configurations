Configuration 'xoap-simple-demo'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'XOAPBaselineModuleDSC'
    Import-DscResource -ModuleName "DSCR_Shortcut"
    Import-DscResource -ModuleName "cShortcut"

    Node "xoap-simple-demo"
    {
        Shortcut "StoreFrontShorcut"
        {
            Ensure = "Present"
            ShortCutName = "C:\Users\Public\Desktop\XOAP-Demo-StoreFront.lnk"
            Executable = "https://storefront.demo.infraxo-dev.com"
            Description = "StoreFront Shortcut"
            IconLocation = "%SystemRoot%\system32\SHELL32.dll,263"
        }

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