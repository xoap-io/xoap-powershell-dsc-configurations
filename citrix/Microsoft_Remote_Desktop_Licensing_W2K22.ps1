Configuration 'Microsoft_Remote_Desktop_Licensing'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'Microsoft_Remote_Desktop_Licensing'
    {
        # Install required Windows features for RDS Licensing
        $features = @('RDS-Licensing','RDS-Licensing-UI')
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Ensure RDS Licensing service is running and set to automatic
        Service 'TermServLicensing' {
            Name        = 'TermServLicensing'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # RDS Licensing - Set license mode (2 = Per User, 4 = Per Device)
        Registry 'RDLicenseMode' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM'
            Ensure      = 'Present'
            ValueName   = 'LicensingMode'
            ValueType   = 'DWORD'
            ValueData   = 2 # Change to 4 for Per Device
        }

        # RDS Licensing - Set license server name(s)
        Registry 'RDLicenseServer' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters'
            Ensure      = 'Present'
            ValueName   = 'LicenseServers'
            ValueType   = 'MultiString'
            ValueData   = @('YourLicenseServerFQDN') # Replace with actual server name(s)
        }

        # RDS Licensing - Enable auditing of licensing events
        Registry 'AuditRDSLicensing' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermServLicensing\Parameters'
            Ensure      = 'Present'
            ValueName   = 'AuditEvents'
            ValueType   = 'DWORD'
            ValueData   = 1
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
Microsoft_Remote_Desktop_Licensing
