Configuration 'Citrix_Workspace_Environment_Management'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_Workspace_Environment_Management'
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

        # Create WEM installation directory
        File 'WEMInstallDirectory' {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\Program Files (x86)\Citrix\Workspace Environment Management Agent'
        }

        # Create WEM log directory
        File 'WEMLogDirectory' {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\Program Files (x86)\Citrix\Workspace Environment Management Agent\Logs'
        }

        # Create WEM cache directory
        File 'WEMCacheDirectory' {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\Citrix\WEM'
        }

        # Ensure Citrix WEM Agent Service is running and set to automatic
        Service 'CitrixWEMAgent' {
            Name        = 'Norskale Agent Host Service'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # WEM Agent Host Service (alternative service name)
        Service 'WEMAgentHostService' {
            Name        = 'WemAgentSvc'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Registry settings for WEM Agent configuration
        Registry 'WEMAgentServerPort' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'AgentServerPort'
            ValueType   = 'DWORD'
            ValueData   = 8286
        }

        # WEM Agent Cache Refresh Delay
        Registry 'WEMAgentCacheRefreshDelay' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'AgentCacheRefreshDelay'
            ValueType   = 'DWORD'
            ValueData   = 30
        }

        # WEM Agent SQL Check Delay
        Registry 'WEMAgentSQLCheckDelay' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'AgentSQLCheckDelay'
            ValueType   = 'DWORD'
            ValueData   = 30
        }

        # WEM Agent Logging Settings
        Registry 'WEMAgentLogLevel' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'LogLevel'
            ValueType   = 'DWORD'
            ValueData   = 0  # 0=Off, 1=Error, 2=Info, 3=Debug
        }

        # WEM Agent Max Log File Size
        Registry 'WEMAgentMaxLogFileSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'MaxLogFileSize'
            ValueType   = 'DWORD'
            ValueData   = 10485760  # 10MB
        }

        # WEM Agent Log File Settings
        Registry 'WEMAgentDeleteOldLogFiles' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'DeleteOldLogFiles'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # WEM Agent Log Retention Settings
        Registry 'WEMAgentDaysToKeepLogFiles' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'DaysToKeepLogFiles'
            ValueType   = 'DWORD'
            ValueData   = 7
        }

        # WEM Agent Performance Optimizations
        Registry 'WEMAgentUseCacheEvenIfOnline' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'UseCacheEvenIfOnline'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # WEM Agent Launch Timeout
        Registry 'WEMAgentLaunchTimeout' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'LaunchTimeout'
            ValueType   = 'DWORD'
            ValueData   = 30000  # 30 seconds
        }

        # WEM Agent UI Settings
        Registry 'WEMAgentUIAgentTimeout' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'UIAgentTimeout'
            ValueType   = 'DWORD'
            ValueData   = 30000  # 30 seconds
        }

        # WEM Database Connection Settings (these would typically be set during installation)
        Registry 'WEMDatabaseServer' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'Broker'
            ValueType   = 'String'
            ValueData   = 'WEM-SERVER'  # Replace with actual WEM infrastructure server
        }

        # WEM Cloud Connector Settings
        Registry 'WEMCloudConnector' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'CloudConnector'
            ValueType   = 'DWORD'
            ValueData   = 0  # 0=On-premises, 1=Cloud
        }

        # WEM Agent Security Settings
        Registry 'WEMAgentEncryptionEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'EnableAgentEncryption'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # WEM Agent SSL Settings
        Registry 'WEMAgentSSLEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'EnableSSL'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # WEM Agent Assignment Settings
        Registry 'WEMSiteGUID' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'AgentSiteGuid'
            ValueType   = 'String'
            ValueData   = ''  # To be populated during deployment
        }

        # WEM Event Log Configuration
        Registry 'WEMEventLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 67108864  # 64MB
        }

        # WEM User Environment Agent specific settings
        Registry 'WEMUserAgentStartupDelay' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'UserAgentStartupDelay'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # WEM User Agent Launch Exclude Groups
        Registry 'WEMUserAgentLaunchExcludeGroups' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'UserAgentLaunchExcludeGroups'
            ValueType   = 'String'
            ValueData   = ''
        }

        # Enable WEM Statistics
        Registry 'WEMEnableStatistics' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'EnableStatistics'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # WEM Cache Management
        Registry 'WEMCacheFileLocation' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'CacheFileLocation'
            ValueType   = 'String'
            ValueData   = 'C:\ProgramData\Citrix\WEM\Cache'
        }

        # Enable Cache File Backup
        Registry 'WEMEnableCacheFileBackup' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure      = 'Present'
            ValueName   = 'EnableCacheFileBackup'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
