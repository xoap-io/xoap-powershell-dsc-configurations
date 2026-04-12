# DSC Configuration: xoap-manager-config-w11-24h2
# Purpose: XOAP manager and executive productivity workstation configuration for Windows 11 24H2.
Configuration 'xoap-manager-config-w11-24h2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-manager-config-w11-24h2'
    {
        # --- Windows Optional Features: Productivity-focused ---
        WindowsOptionalFeature 'HyperV'
        {
            Name   = 'Microsoft-Hyper-V-All'
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

        # --- Registry: Disable Consumer Features ---
        Registry 'DisableConsumerFeatures'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Auto-lock screen saver (10 min — more lenient than consultant 5 min) ---
        Registry 'ScreenSaver_Active'
        {
            Key       = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
            Ensure    = 'Present'
            ValueName = 'ScreenSaveActive'
            ValueType = 'String'
            ValueData = '1'
        }

        Registry 'ScreenSaver_Secure'
        {
            Key       = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
            Ensure    = 'Present'
            ValueName = 'ScreenSaverIsSecure'
            ValueType = 'String'
            ValueData = '1'
        }

        Registry 'ScreenSaver_Timeout'
        {
            Key       = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
            Ensure    = 'Present'
            ValueName = 'ScreenSaveTimeOut'
            ValueType = 'String'
            ValueData = '600'
        }

        # --- Registry: OneDrive auto-start allowed (managers use OneDrive) ---
        Registry 'OneDrive_AllowAutoStart'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive'
            Ensure    = 'Present'
            ValueName = 'DisablePersonalSync'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Services ---
        Service 'WSearch_Running'
        {
            Name        = 'WSearch'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'RemoteRegistry_Disabled'
        {
            Name        = 'RemoteRegistry'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }
    }
}
xoap-manager-config-w11-24h2 -OutputPath 'C:\DSC\xoap-manager-config-w11-24h2'
