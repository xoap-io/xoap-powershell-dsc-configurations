# DSC Configuration: xoap-consultant-config-vdi-w11-24h2
# Purpose: XOAP consultant workstation configuration for Windows 11 24H2 VDI deployments.
Configuration 'xoap-consultant-config-vdi-w11-24h2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-consultant-config-vdi-w11-24h2'
    {
        # --- Windows Optional Features (no nested Hyper-V in VDI) ---
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

        # --- Registry: Auto-lock screen saver (5 min) ---
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
            ValueData = '300'
        }

        # --- Registry: VDI Power (no sleep/hibernate) ---
        Registry 'Power_DCSleepDisabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
            Ensure    = 'Present'
            ValueName = 'DCSettingIndex'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Power_ACSleepDisabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
            Ensure    = 'Present'
            ValueName = 'ACSettingIndex'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Time Zone Redirection ---
        Registry 'RDP_TimeZoneRedirection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fEnableTimeZoneRedirection'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Clipboard Redirection Allowed ---
        Registry 'RDP_ClipboardAllowed'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableClip'
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
    }
}
xoap-consultant-config-vdi-w11-24h2 -OutputPath 'C:\DSC\xoap-consultant-config-vdi-w11-24h2'
