Configuration 'Citrix_Universal_Print_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_Universal_Print_Server'
    {
        $features = @(
            'Print-Services',
            'Print-Server'
        )
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Ensure Print Spooler service is running and set to automatic
        Service 'Spooler' {
            Name        = 'Spooler'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Storage - Disable Storage Spaces Direct (if not used)
        Registry 'DisableS2D' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\S2D'
            Ensure      = 'Present'
            ValueName   = 'Start'
            ValueType   = 'DWORD'
            ValueData   = 4
        }

        # Universal Print Server - Enable logging for troubleshooting
        Registry 'UPSLogging' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UniversalPrintServer\Logging'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Print driver isolation (recommended for stability)
        Registry 'PrintDriverIsolation' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers'
            Ensure      = 'Present'
            ValueName   = 'IsolationMode'
            ValueType   = 'DWORD'
            ValueData   = 2
        }
        
        # Enable auditing for print events
        Registry 'AuditPrintEvents' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler'
            Ensure      = 'Present'
            ValueName   = 'AuditEvents'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
