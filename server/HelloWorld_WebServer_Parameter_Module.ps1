Configuration HelloWorld_WebServer_Parameter_Module
{
    # param
    # (
    #     [String]
    #     $TestParameter="TestParameterValue"
    # )

Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
Import-DscResource -ModuleName 'WebAdministrationDSC' -ModuleVersion '4.1.0'

    Node HelloWorld_WebServer_Parameter_Module 
    {
        File 'TestFile' 
        {
            Ensure = "Present"
            DestinationPath = "c:\temp\HelloWorld.txt"
            Contents = "Hello World!$TestParameter"
        }

        WindowsFeature 'WebServer'
        {
            Name = "Web-Server"
            Ensure = "Present"
        }

        WindowsFeature 'ManagementTools'
        {
            Name = "Web-Mgmt-Tools"
            Ensure = "Present"
        }

        WindowsFeature 'DefaultDoc'
        {
            Name = "Web-Default-Doc"
            Ensure = "Present"
        }

        Website 'DefaultSite'
        {
            Ensure          = "Present"
            Name            = "Default Web Site"
            State           = "Stopped"
            PhysicalPath    = "C:\https"
            DependsOn       = "[WindowsFeature]WebServer"
        }
    }
}
HelloWorld_WebServer_Parameter_Module