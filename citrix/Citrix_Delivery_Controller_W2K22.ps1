Configuration 'Citrix_Delivery_Controller'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'Citrix_Delivery_Controller'
    {
        # Required Windows features for Delivery Controller
        $features = @(
            'Web-Server','Web-WebServer','Web-Common-Http','Web-Default-Doc','Web-Static-Content','Web-Http-Redirect',
            'Web-Http-Logging','Web-Security','Web-Filtering','Web-Basic-Auth','Web-Windows-Auth','Web-App-Dev','Web-Net-Ext45',
            'Web-AppInit','Web-Asp-Net45','Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Mgmt-Tools','Web-Mgmt-Console','Web-Scripting-Tools',
            'NET-Framework-45-ASPNET','RSAT-AD-PowerShell','Remote-Assistance','WAS','WAS-Process-Model','WAS-Config-APIs'
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

        # Windows Server 2022 specific optimizations
        # Disable SMBv1
        Registry 'SMBv1' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'SMB1'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Disable Defender if using 3rd party AV
        Registry 'DisableDefender' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
            Ensure      = 'Present'
            ValueName   = 'DisableAntiSpyware'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Telemetry
        Registry 'Telemetry' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure      = 'Present'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Power Plan - High Performance
        Registry 'PowerPlan' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' # High Performance GUID
        }
        # Event Log - Limit log size
        Registry 'ApplicationLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }
        Registry 'SystemLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }
        # Network - TCP/IP tuning
        Registry 'TcpAutoTuning' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableTCPA'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Storage - Disable Storage Spaces Direct (if not used)
        Registry 'DisableS2D' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\S2D'
            Ensure      = 'Present'
            ValueName   = 'Start'
            ValueType   = 'DWORD'
            ValueData   = 4
        }
        # Security - Harden LSA
        Registry 'RunAsPPL' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure      = 'Present'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Security - Credential Guard
        Registry 'EnableVirtualizationBasedSecurity' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        Registry 'RequirePlatformSecurityFeatures' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'RequirePlatformSecurityFeatures'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
Citrix_Delivery_Controller
