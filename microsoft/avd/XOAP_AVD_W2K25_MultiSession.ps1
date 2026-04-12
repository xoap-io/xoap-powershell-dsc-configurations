# DSC Configuration: XOAP_AVD_W2K25_MultiSession
# Purpose: Azure Virtual Desktop multi-session configuration for Windows Server 2025.
Configuration 'XOAP_AVD_W2K25_MultiSession'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_AVD_W2K25_MultiSession'
    {
        # --- Windows Features (Server 2025 uses WindowsFeature not WindowsOptionalFeature) ---
        WindowsFeature 'RDS_RD_Server'
        {
            Name   = 'RDS-RD-Server'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'TermService'
        {
            Name        = 'TermService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

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

        # --- Registry: NLA Required ---
        Registry 'AVD_NLA_Required'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'UserAuthentication'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Session Limits ---
        Registry 'AVD_MaxIdleTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxIdleTime'
            ValueType = 'Dword'
            ValueData = '3600000'
        }

        Registry 'AVD_MaxDisconnectionTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxDisconnectionTime'
            ValueType = 'Dword'
            ValueData = '900000'
        }

        Registry 'AVD_MaxConnectionTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxConnectionTime'
            ValueType = 'Dword'
            ValueData = '28800000'
        }

        # --- Registry: Clipboard and Drive Redirection ---
        Registry 'AVD_ClipboardEnabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableClip'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'AVD_DriveRedirectionEnabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableCdm'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Time Zone Redirection ---
        Registry 'AVD_TimeZoneRedirection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fEnableTimeZoneRedirection'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Teams Classic Multi-Session Optimization ---
        Registry 'Teams_ClassicMultiSession'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams'
            Ensure    = 'Present'
            ValueName = 'IsWVDEnvironment'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Power (no sleep in AVD) ---
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

        # --- Registry: W2K25-specific: Disable Recall ---
        Registry 'AVD_DisableRecall'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Ensure    = 'Present'
            ValueName = 'AllowRecall'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: W2K25-specific: LSA PPL (locked mode) ---
        Registry 'LSA_RunAsPPL'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure    = 'Present'
            ValueName = 'RunAsPPL'
            ValueType = 'Dword'
            ValueData = '2'
        }
    }
}
XOAP_AVD_W2K25_MultiSession -OutputPath 'C:\DSC\XOAP_AVD_W2K25_MultiSession'
