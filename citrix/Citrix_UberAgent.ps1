Configuration 'UberAgent_W2K22'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'UberAgent_W2K22'
    {
        # Enable network tracking in uberAgent
        Registry 'UberAgentNetworkTracking' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableNetworkTracking'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable process tracking in uberAgent
        Registry 'UberAgentProcessTracking' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableProcessTracking'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable user experience tracking in uberAgent
        Registry 'UberAgentUserExperienceTracking' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableUserExperienceTracking'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # uberAgent Data Forwarding Settings
        Registry 'UberAgentSplunkForwarder' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'SplunkForwarderEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Set Splunk server for uberAgent data forwarding
        Registry 'UberAgentSplunkServer' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'SplunkServer'
            ValueType   = 'String'
            ValueData   = 'splunk-server:9997'  # Replace with actual Splunk server
        }

        # Enable SSL for Splunk forwarding in uberAgent
        Registry 'UberAgentSplunkSSL' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'SplunkSSLEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # uberAgent Browser Metrics Settings
        Registry 'UberAgentBrowserMetrics' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableBrowserMetrics'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable web app tracking in uberAgent
        Registry 'UberAgentWebAppTracking' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableWebAppTracking'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # uberAgent Session Monitoring
        Registry 'UberAgentSessionMetrics' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableSessionMetrics'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable GPU metrics collection in uberAgent
        Registry 'UberAgentGPUMetrics' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableGPUMetrics'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Anonymize usernames in uberAgent data
        Registry 'UberAgentAnonymizeUsers' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'AnonymizeUsernames'
            ValueType   = 'DWORD'
            ValueData   = 0  # Set to 1 to anonymize usernames
        }

        # Set local data retention days for uberAgent
        Registry 'UberAgentDataRetention' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'LocalDataRetentionDays'
            ValueType   = 'DWORD'
            ValueData   = 30
        }

        # uberAgent Endpoint Security Analytics (ESA) Settings
        Registry 'UberAgentESAEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'ESAEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable threat detection in uberAgent
        Registry 'UberAgentThreatDetection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableThreatDetection'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable file hashing in uberAgent
        Registry 'UberAgentFileHashingEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableFileHashing'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Exclude uberAgent install directory from Windows Defender
        Registry 'DefenderExclusionPath' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
            Ensure      = 'Present'
            ValueName   = 'C:\Program Files\vast limits\uberAgent'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Exclude uberAgent data directory from Windows Defender
        Registry 'DefenderExclusionDataPath' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
            Ensure      = 'Present'
            ValueName   = 'C:\ProgramData\uberAgent'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Enable Citrix optimization in uberAgent
        Registry 'UberAgentCitrixOptimization' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'CitrixOptimizationEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable VDA tracking in uberAgent (Citrix)
        Registry 'UberAgentVDATracking' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableVDATracking'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable VMware optimization in uberAgent
        Registry 'UberAgentVMwareOptimization' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'VMwareOptimizationEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Disable System Restore for performance
        Registry 'DisableSystemRestore' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
            Ensure      = 'Present'
            ValueName   = 'DisableSR'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Optimize for background services
        Registry 'OptimizeForBackgroundServices' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl'
            Ensure      = 'Present'
            ValueName   = 'Win32PrioritySeparation'
            ValueType   = 'DWORD'
            ValueData   = 24
        }

        # Enable CPU throttling in uberAgent
        Registry 'UberAgentCPUThrottling' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'CPUThrottlingEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Set maximum CPU usage for uberAgent
        Registry 'UberAgentMaxCPUUsage' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'MaxCPUUsagePercent'
            ValueType   = 'DWORD'
            ValueData   = 10  # Maximum 10% CPU usage
        }

        # Set maximum memory usage for uberAgent
        Registry 'UberAgentMaxMemoryMB' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'MaxMemoryUsageMB'
            ValueType   = 'DWORD'
            ValueData   = 512  # Maximum 512MB memory usage
        }

        # Anonymize user names in uberAgent
        Registry 'UberAgentAnonymizeUsers' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'AnonymizeUsernames'
            ValueType   = 'DWORD'
            ValueData   = 0  # Set to 1 to anonymize usernames
        }
        # Data Retention Settings
        Registry 'UberAgentDataRetention' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'LocalDataRetentionDays'
            ValueType   = 'DWORD'
            ValueData   = 30
        }

        # uberAgent Endpoint Security Analytics (ESA) Settings
        Registry 'UberAgentESAEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'ESAEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # uberAgent Threat Detection Settings
        Registry 'UberAgentThreatDetection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableThreatDetection'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # uberAgent File Hashing Settings
        Registry 'UberAgentFileHashingEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableFileHashing'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable Windows Defender exclusions for uberAgent (if using Defender)
        Registry 'DefenderExclusionPath' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
            Ensure      = 'Present'
            ValueName   = 'C:\Program Files\vast limits\uberAgent'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # uberAgent Data Exclusion Settings
        Registry 'DefenderExclusionDataPath' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
            Ensure      = 'Present'
            ValueName   = 'C:\ProgramData\uberAgent'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # uberAgent Citrix-specific settings (if in Citrix environment)
        Registry 'UberAgentCitrixOptimization' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'CitrixOptimizationEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable VDA tracking in uberAgent (Citrix)
        Registry 'UberAgentVDATracking' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'EnableVDATracking'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # uberAgent VMware-specific settings (if in VMware environment)
        Registry 'UberAgentVMwareOptimization' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'VMwareOptimizationEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Disable System Restore for performance
        Registry 'DisableSystemRestore' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
            Ensure      = 'Present'
            ValueName   = 'DisableSR'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Optimize for background services
        Registry 'OptimizeForBackgroundServices' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl'
            Ensure      = 'Present'
            ValueName   = 'Win32PrioritySeparation'
            ValueType   = 'DWORD'
            ValueData   = 24
        }

        # uberAgent CPU and Memory optimization
        Registry 'UberAgentCPUThrottling' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'CPUThrottlingEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Set maximum CPU usage for uberAgent
        Registry 'UberAgentMaxCPUUsage' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'MaxCPUUsagePercent'
            ValueType   = 'DWORD'
            ValueData   = 10  # Maximum 10% CPU usage
        }

        # Set maximum memory usage for uberAgent
        Registry 'UberAgentMaxMemoryMB' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\vast limits\uberAgent'
            Ensure      = 'Present'
            ValueName   = 'MaxMemoryUsageMB'
            ValueType   = 'DWORD'
            ValueData   = 512  # Maximum 512MB memory usage
        }
    }
}
