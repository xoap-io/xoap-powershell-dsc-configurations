Configuration 'Citrix_Delivery_Controller'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_Delivery_Controller'
    {
        # Required Windows features for Delivery Controller
        $features = @(
            'Web-Server',
            'Web-WebServer',
            'Web-Common-Http',
            'Web-Default-Doc',
            'Web-Static-Content',
            'Web-Http-Redirect',
            'Web-Http-Logging',
            'Web-Security',
            'Web-Filtering',
            'Web-Basic-Auth',
            'Web-Windows-Auth',
            'Web-App-Dev',
            'Web-Net-Ext45',
            'Web-AppInit',
            'Web-Asp-Net45',
            'Web-ISAPI-Ext',
            'Web-ISAPI-Filter',
            'Web-Mgmt-Tools',
            'Web-Mgmt-Console',
            'Web-Scripting-Tools',
            'NET-Framework-45-ASPNET',
            'RSAT-AD-PowerShell',
            'Remote-Assistance',
            'WAS',
            'WAS-Process-Model',
            'WAS-Config-APIs'
        )
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Ensure Citrix Broker Service is running and set to automatic
        Service 'CitrixBrokerService' {
            Name        = 'CitrixBrokerService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Ensure Citrix Configuration Logging Service is running and set to automatic
        Service 'CitrixConfigLoggingService' {
            Name        = 'CitrixConfigLoggingService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Ensure Citrix Host Service is running and set to automatic
        Service 'CitrixHostService' {
            Name        = 'CitrixHostService'
            State       = 'Running'
            StartupType = 'Automatic'
        }
   }
}
