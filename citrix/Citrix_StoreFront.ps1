Configuration 'Citrix_StoreFront'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_StoreFront'
    {
        $features = @(
            'Web-Server',
            'Web-WebServer',
            'Web-Default-Doc',
            'Web-Http-Errors',
            'Web-Static-Content',
            'Web-Http-Redirect',
            'Web-Health',
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
            'NET-Framework-45-ASPNET'
        )
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Ensure IIS service is running and set to automatic
        Service 'W3SVC' {
            Name        = 'W3SVC'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Ensure Citrix StoreFront service is running and set to automatic
        Service 'CitrixStoreFront' {
            Name        = 'CitrixStoreFront'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Enable StoreFront logging for troubleshooting
        Registry 'StoreFrontLogging' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\DeliveryServices\Logging'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
