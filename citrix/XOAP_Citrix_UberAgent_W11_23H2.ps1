# DSC Configuration: XOAP_Citrix_UberAgent_W11_23H2
# Purpose: Installs and configures Citrix UberAgent on Windows 11 23H2.
Configuration 'XOAP_Citrix_UberAgent_W11_23H2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Citrix_UberAgent_W11_23H2'
    {
        # Ensure UberAgent service is running
        Service 'UberAgentService'
        {
            Name        = 'uberAgent'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # UberAgent data directory
        File 'UberAgentDataDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\Citrix\UberAgent'
        }

        # UberAgent log directory
        File 'UberAgentLogDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\Citrix\UberAgent\Logs'
        }

        # UberAgent configuration directory
        File 'UberAgentConfigDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\Program Files\Citrix\UberAgent'
        }

        # Registry: UberAgent log level (Info)
        Registry 'UberAgent_LogLevel'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent'
            Ensure    = 'Present'
            ValueName = 'LogLevel'
            ValueType = 'Dword'
            ValueData = '2'
        }

        # Registry: UberAgent data retention (days)
        Registry 'UberAgent_DataRetention'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent'
            Ensure    = 'Present'
            ValueName = 'DataRetentionDays'
            ValueType = 'Dword'
            ValueData = '30'
        }

        # Registry: UberAgent telemetry collection interval (seconds)
        Registry 'UberAgent_CollectionInterval'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent'
            Ensure    = 'Present'
            ValueName = 'CollectionIntervalSec'
            ValueType = 'Dword'
            ValueData = '30'
        }

        # Registry: UberAgent splunk forwarding enabled
        Registry 'UberAgent_SplunkEnabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent\Splunk'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # Registry: UberAgent logon simulation enabled
        Registry 'UberAgent_LogonSimulation'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent\LogonSimulator'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # Registry: UberAgent session recording
        Registry 'UberAgent_SessionRecording'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent\SessionRecording'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # Registry: UberAgent process tracking
        Registry 'UberAgent_ProcessTracking'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent\ProcessTracking'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # Registry: UberAgent network tracking
        Registry 'UberAgent_NetworkTracking'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent\NetworkTracking'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # Windows Firewall: Allow UberAgent default port 9514 inbound
        Registry 'UberAgent_FirewallPort'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UberAgent\Network'
            Ensure    = 'Present'
            ValueName = 'ListenPort'
            ValueType = 'Dword'
            ValueData = '9514'
        }
    }
}
XOAP_Citrix_UberAgent_W11_23H2 -OutputPath 'C:\DSC\XOAP_Citrix_UberAgent_W11_23H2'
