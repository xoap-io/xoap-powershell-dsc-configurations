
Configuration XOAP_Citrix_StoreFront
{
Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node XOAP_Citrix_StoreFront
    {
        WindowsFeature 'Web-Server'
        {
            Name    = 'Web-Server'
            Ensure  = 'Present'
        }
        
        WindowsFeature 'Web-WebServer'
        {
            Name    = 'Web-WebServer'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Default-Doc'
        {
            Name    = 'Web-Default-Doc'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Http-Errors'
        {
            Name    = 'Web-Http-Errors'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Static-Content'
        {
            Name    = 'Web-Static-Content'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Http-Redirect'
        {
            Name    = 'Web-Http-Redirect'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Health'
        {
            Name    = 'Web-Health'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Http-Logging'
        {
            Name    = 'Web-Http-Logging'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Security'
        {
            Name    = 'Web-Security'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Filtering'
        {
            Name    = 'Web-Filtering'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Basic-Auth'
        {
            Name    = 'Web-Basic-Auth'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Windows-Auth'
        {
            Name    = 'Web-Windows-Auth'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-App-Dev'
        {
            Name    = 'Web-App-Dev'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Net-Ext45'
        {
            Name    = 'Web-Net-Ext45'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-AppInit'
        {
            Name    = 'Web-AppInit'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Asp-Net45'
        {
            Name    = 'Web-Asp-Net45'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-ISAPI-Ext'
        {
            Name    = 'Web-ISAPI-Ext'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-ISAPI-Filter'
        {
            Name    = 'Web-ISAPI-Filter'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Mgmt-Tools'
        {
            Name    = 'Web-Mgmt-Tools'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Mgmt-Console'
        {
            Name    = 'Web-Mgmt-Console'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Scripting-Tools'
        {
            Name    = 'Web-Scripting-Tools'
            Ensure  = 'Present'
        }

        WindowsFeature 'NET-Framework-45-ASPNET'
        {
            Name    = 'NET-Framework-45-ASPNET'
            Ensure  = 'Present'
        }
    }
}
XOAP_Citrix_StoreFront