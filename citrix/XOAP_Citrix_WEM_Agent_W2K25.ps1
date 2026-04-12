# DSC Configuration: XOAP_Citrix_WEM_Agent_W2K25
# Purpose: Configures Citrix Workspace Environment Management Agent on Windows Server 2025.
Configuration 'XOAP_Citrix_WEM_Agent_W2K25'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Citrix_WEM_Agent_W2K25'
    {
        # --- Services: WEM Agent ---
        Service 'WEMAgentHostService'
        {
            Name        = 'Citrix WEM Agent Host Service'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'WEMMessageCenter'
        {
            Name        = 'Citrix WEM Message Center Service'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- File: WEM Cache Directory ---
        File 'WEMCacheDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\Norskale\Agent Host\Cache'
        }

        # --- Registry: WEM Agent Configuration ---
        Registry 'WEM_BrokerPort'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure    = 'Present'
            ValueName = 'AgentPort'
            ValueType = 'Dword'
            ValueData = '4502'
        }

        Registry 'WEM_RefreshInterval'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure    = 'Present'
            ValueName = 'AgentCacheRefreshDelay'
            ValueType = 'Dword'
            ValueData = '30'
        }

        Registry 'WEM_CachePath'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure    = 'Present'
            ValueName = 'AgentCachePath'
            ValueType = 'String'
            ValueData = 'C:\ProgramData\Norskale\Agent Host\Cache'
        }

        # --- Registry: W2K25-specific — Force TLS 1.3 for WEM Agent Broker ---
        Registry 'WEM_BrokerTlsVersion'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Norskale\Agent Host'
            Ensure    = 'Present'
            ValueName = 'WEMAgentBrokerTlsVersion'
            ValueType = 'String'
            ValueData = 'TLS1.3'
        }
    }
}
XOAP_Citrix_WEM_Agent_W2K25 -OutputPath 'C:\DSC\XOAP_Citrix_WEM_Agent_W2K25'
