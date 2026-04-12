# DSC Configuration: xoap-w11-24h2-packaging-workstation-vdi
# Purpose: XOAP W11 24H2 VDI golden image packaging workstation configuration.
Configuration 'xoap-w11-24h2-packaging-workstation-vdi'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-w11-24h2-packaging-workstation-vdi'
    {
        # --- Windows Optional Features ---
        WindowsOptionalFeature 'HyperV'
        {
            Name   = 'Microsoft-Hyper-V-All'
            Ensure = 'Enable'
        }

        WindowsOptionalFeature 'Containers'
        {
            Name   = 'Containers'
            Ensure = 'Enable'
        }

        WindowsOptionalFeature 'NetFx3'
        {
            Name   = 'NetFx3'
            Ensure = 'Enable'
        }

        # --- Registry: Disable Recall ---
        Registry 'DisableRecall'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Ensure    = 'Present'
            ValueName = 'AllowRecall'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Disable Copilot ---
        Registry 'DisableCopilot'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
            Ensure    = 'Present'
            ValueName = 'TurnOffWindowsCopilot'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Disable Consumer Content ---
        Registry 'DisableConsumerFeatures'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Disable Auto-Updates During Packaging ---
        Registry 'WU_NoAutoUpdate'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure    = 'Present'
            ValueName = 'NoAutoUpdate'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Disable Defender Real-Time During Image Capture ---
        Registry 'Defender_DisableRealtime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            Ensure    = 'Present'
            ValueName = 'DisableRealtimeMonitoring'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Services ---
        Service 'WindowsUpdate_Running'
        {
            Name        = 'wuauserv'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'WSearch_Stopped'
        {
            Name        = 'WSearch'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }
    }
}
xoap-w11-24h2-packaging-workstation-vdi -OutputPath 'C:\DSC\xoap-w11-24h2-packaging-workstation-vdi'
