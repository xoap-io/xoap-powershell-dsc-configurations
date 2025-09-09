Configuration 'XOAP_Citrix_WEM_Agent'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Citrix_WEM_Agent'
    {
        # Required Windows features for WEM
        $features = @(
            'NET-Framework-45-Core',
            'NET-Framework-45-ASPNET'
        )
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # WEM Agent Service
        Service 'CitrixWEMAgent' {
            Name        = 'Norskale Agent Host Service'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Core WEM Registry Settings
        Registry 'WEMAgentServerPort' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'AgentServerPort'
            ValueType   = 'DWORD'
            ValueData   = 8286
        }

        Registry 'WEMDatabaseServer' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'Broker'
            ValueType   = 'String'
            ValueData   = 'WEM-SERVER'
        }

        Registry 'WEMAgentLogLevel' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'LogLevel'
            ValueType   = 'DWORD'
            ValueData   = 1  # Error level logging
        }

        Registry 'WEMAgentEncryptionEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'EnableAgentEncryption'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # High Performance Power Plan
        Registry 'HighPerformancePowerPlan' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        }

        # Windows Time Service
        Service 'W32Time' {
            Name        = 'W32Time'
            State       = 'Running'
            StartupType = 'Automatic'
        }
    }
}
