
# DSC Configuration: HelloWorld_WebServer_Parameter_Module
# Purpose: Installs IIS and related features, creates a test file, and configures the default website.
Configuration 'HelloWorld_WebServer_Parameter_Module'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'WebAdministrationDSC' -ModuleVersion '4.1.0'

    Node 'HelloWorld_WebServer_Parameter_Module'
    {
        # Creates a test file with optional parameter content
        File 'HelloWorld_TestFile' 
        {
            Ensure          = "Present"
            DestinationPath = "C:\temp\HelloWorld.txt"
            Contents        = "Hello World!"
        }

        # Installs IIS Web-Server feature
        WindowsFeature 'IIS_WebServer'
        {
            Name    = "Web-Server"
            Ensure  = "Present"
        }

        # Installs IIS Management Tools
        WindowsFeature 'IIS_ManagementTools'
        {
            Name    = "Web-Mgmt-Tools"
            Ensure  = "Present"
        }

        # Installs IIS Default Document feature
        WindowsFeature 'IIS_DefaultDoc'
        {
            Name    = "Web-Default-Doc"
            Ensure  = "Present"
        }

        # Configures the default website and stops it
        Website 'IIS_DefaultSite'
        {
            Ensure       = "Present"
            Name         = "Default Web Site"
            State        = "Stopped"
            PhysicalPath = "C:\https"
            DependsOn    = "[WindowsFeature]IIS_WebServer"
        }
    }
}
