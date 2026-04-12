# DSC Configuration: XOAP_AVD_W11_23H2_SessionHost
# Purpose: Configures a Windows 11 23H2 Azure Virtual Desktop session host.
Configuration 'XOAP_AVD_W11_23H2_SessionHost'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc'   -ModuleVersion '1.2.0'

    Node 'XOAP_AVD_W11_23H2_SessionHost'
    {
        # --- Windows Features ---
        WindowsOptionalFeature 'RDS-RD-Server'
        {
            Name   = 'Microsoft-Windows-RemoteDesktopServices-RdSession'
            Ensure = 'Enable'
        }

        # --- Teams Media Optimization ---
        Registry 'Teams_IsAVDEnvironment'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams'
            Ensure    = 'Present'
            ValueName = 'IsAVDEnvironment'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Teams_WebRTC_AVD'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams'
            Ensure    = 'Present'
            ValueName = 'DisableFallback'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Windows Update for Business (defer feature updates 180 days) ---
        Registry 'WU_DeferFeatureUpdatesPeriod'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            Ensure    = 'Present'
            ValueName = 'DeferFeatureUpdatesPeriodInDays'
            ValueType = 'Dword'
            ValueData = '180'
        }

        Registry 'WU_DeferQualityUpdatesPeriod'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            Ensure    = 'Present'
            ValueName = 'DeferQualityUpdatesPeriodInDays'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Power: Disable sleep/hibernate on session host ---
        Registry 'Power_StandbyDC'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
            Ensure    = 'Present'
            ValueName = 'DCSettingIndex'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Power_StandbyAC'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
            Ensure    = 'Present'
            ValueName = 'ACSettingIndex'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Multi-session: allow concurrent sessions ---
        Registry 'RDS_MaxSessionsPerUser'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fSingleSessionPerUser'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Session limits ---
        Registry 'RDS_MaxIdleTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxIdleTime'
            ValueType = 'Dword'
            ValueData = '3600000'
        }

        Registry 'RDS_MaxDisconnectionTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxDisconnectionTime'
            ValueType = 'Dword'
            ValueData = '900000'
        }

        # --- NLA Required ---
        Registry 'RDS_NLA'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'UserAuthentication'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- RemoteFX GPU ---
        Registry 'RDS_RemoteFX_Enable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'AVC444ModePreferred'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Clipboard redirection allowed ---
        Registry 'RDS_ClipboardRedirection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableClip'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Drive redirection disabled for security ---
        Registry 'RDS_DriveRedirection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableCdm'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Disable Windows Copilot (present in 23H2) ---
        Registry 'DisableCopilot'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
            Ensure    = 'Present'
            ValueName = 'TurnOffWindowsCopilot'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Start menu: disable consumer features ---
        Registry 'StartMenu_DisableConsumerFeatures'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Search: disable web results ---
        Registry 'Search_DisableWebSearch'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure    = 'Present'
            ValueName = 'DisableWebSearch'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Time zone redirection ---
        Registry 'RDS_TimeZoneRedirection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fEnableTimeZoneRedirection'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Disable autoplay ---
        Registry 'DisableAutoPlay'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            Ensure    = 'Present'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'Dword'
            ValueData = '255'
        }

        # --- Services ---
        Service 'RdAgent'
        {
            Name        = 'RdAgent'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'WindowsAzureGuestAgent'
        {
            Name        = 'WindowsAzureGuestAgent'
            State       = 'Running'
            StartupType = 'Automatic'
        }
    }
}
XOAP_AVD_W11_23H2_SessionHost -OutputPath 'C:\DSC\XOAP_AVD_W11_23H2_SessionHost'
