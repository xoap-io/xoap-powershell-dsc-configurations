Configuration 'Citrix_Licensing'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_Licensing'
    {
        $features = @(
            'RDS-Licensing',
            'RDS-Licensing-UI'
        )
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Ensure RDS Licensing service is running and set to automatic
        Service 'TermServLicensing' 
        {
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
    }
}
