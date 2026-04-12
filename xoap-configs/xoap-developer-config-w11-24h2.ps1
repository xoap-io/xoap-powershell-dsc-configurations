# DSC Configuration: xoap-developer-config-w11-24h2
# Purpose: XOAP developer workstation configuration for Windows 11 24H2.
Configuration 'xoap-developer-config-w11-24h2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-developer-config-w11-24h2'
    {
        # --- Windows Optional Features ---
        WindowsOptionalFeature 'WSL_VirtualMachinePlatform'
        {
            Name   = 'VirtualMachinePlatform'
            Ensure = 'Enable'
        }

        WindowsOptionalFeature 'WSL_Subsystem'
        {
            Name   = 'Microsoft-Windows-Subsystem-Linux'
            Ensure = 'Enable'
        }

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

        WindowsOptionalFeature 'TelnetClient'
        {
            Name   = 'TelnetClient'
            Ensure = 'Enable'
        }

        WindowsOptionalFeature 'DisableIE'
        {
            Name   = 'Internet-Explorer-Optional-amd64'
            Ensure = 'Disable'
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

        # --- Registry: Disable Recall ---
        Registry 'DisableRecall'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Ensure    = 'Present'
            ValueName = 'AllowRecall'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Enable Dark Mode ---
        Registry 'EnableDarkMode'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
            Ensure    = 'Present'
            ValueName = 'AppsUseLightTheme'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Disable Consumer Features ---
        Registry 'DisableConsumerFeatures'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Enable Long Paths ---
        Registry 'EnableLongPaths'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem'
            Ensure    = 'Present'
            ValueName = 'LongPathsEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Services ---
        Service 'RemoteRegistry_Disabled'
        {
            Name        = 'RemoteRegistry'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'WSearch_Disabled'
        {
            Name        = 'WSearch'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }
    }
}
xoap-developer-config-w11-24h2 -OutputPath 'C:\DSC\xoap-developer-config-w11-24h2'
