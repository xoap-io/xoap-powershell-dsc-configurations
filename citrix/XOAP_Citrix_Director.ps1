Configuration 'XOAP_Citrix_Director'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'XOAP_Citrix_Director'
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

        WindowsFeature 'Web-Common-Http'
        {
            Name    = 'Web-Common-Http'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Default-Doc'
        {
            Name    = 'Web-Default-Doc'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Dir-Browsing'
        {
            Name    = 'Web-Dir-Browsing'
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

        WindowsFeature 'Web-Log-Libraries'
        {
            Name    = 'Web-Log-Libraries'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Http-Tracing'
        {
            Name    = 'Web-Http-Tracing'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Performance'
        {
            Name    = 'Web-Performance'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Stat-Compression'
        {
            Name    = 'Web-Stat-Compression'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Dyn-Compression'
        {
            Name    = 'Web-Dyn-Compression'
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

        WindowsFeature 'Web-ASP'
        {
            Name    = 'Web-ASP'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Asp-Net45'
        {
            Name    = 'Web-Asp-Net45'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-CGI'
        {
            Name    = 'Web-CGI'
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

        WindowsFeature 'Web-Includes'
        {
            Name    = 'Web-Includes'
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

        WindowsFeature 'Web-Mgmt-Compat'
        {
            Name    = 'Web-Mgmt-Compat'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Metabase'
        {
            Name    = 'Web-Metabase'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Lgcy-Mgmt-Console'
        {
            Name    = 'Web-Lgcy-Mgmt-Console'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-Lgcy-Scripting'
        {
            Name    = 'Web-Lgcy-Scripting'
            Ensure  = 'Present'
        }

        WindowsFeature 'Web-WMI'
        {
            Name    = 'Web-WMI'
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

        WindowsFeature 'NET-WCF-HTTP-Activation45'
        {
            Name    = 'NET-WCF-HTTP-Activation45'
            Ensure  = 'Present'
        }

        WindowsFeature 'Remote-Assistance'
        {
            Name    = 'Remote-Assistance'
            Ensure  = 'Present'
        }

        WindowsFeature 'WAS'
        {
            Name    = 'WAS'
            Ensure  = 'Present'
        }

        WindowsFeature 'WAS-Process-Model'
        {
            Name    = 'WAS-Process-Model'
            Ensure  = 'Present'
        }

        WindowsFeature 'WAS-Config-APIs'
        {
            Name    = 'WAS-Config-APIs'
            Ensure  = 'Present'
        }
    }
}
XOAP_Citrix_Director