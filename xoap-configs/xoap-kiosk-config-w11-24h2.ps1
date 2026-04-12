# DSC Configuration: xoap-kiosk-config-w11-24h2
# Purpose: XOAP kiosk and frontline worker locked-down workstation configuration for Windows 11 24H2.
Configuration 'xoap-kiosk-config-w11-24h2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-kiosk-config-w11-24h2'
    {
        # --- Windows Optional Features: Minimal footprint ---
        WindowsOptionalFeature 'DisableIE'
        {
            Name   = 'Internet-Explorer-Optional-amd64'
            Ensure = 'Disable'
        }

        WindowsOptionalFeature 'DisableHyperV'
        {
            Name   = 'Microsoft-Hyper-V-All'
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

        # --- Registry: Disable Lock Screen ---
        Registry 'DisableLockScreen'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            Ensure    = 'Present'
            ValueName = 'NoLockScreen'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Disable Taskbar Customization ---
        Registry 'Taskbar_DisableWidgets'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh'
            Ensure    = 'Present'
            ValueName = 'AllowNewsAndInterests'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Single App Kiosk Mode ---
        Registry 'Kiosk_DisableTaskMgr'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Ensure    = 'Present'
            ValueName = 'DisableTaskMgr'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Kiosk_DisableCmdRun'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            Ensure    = 'Present'
            ValueName = 'DisallowRun'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Session Locking ---
        Registry 'Kiosk_InactivityTimeout'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Ensure    = 'Present'
            ValueName = 'InactivityTimeoutSecs'
            ValueType = 'Dword'
            ValueData = '600'
        }

        # --- Registry: Power (no sleep in kiosk) ---
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

        # --- Services: Minimal footprint ---
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

        Service 'XblAuthManager_Disabled'
        {
            Name        = 'XblAuthManager'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'XboxNetApiSvc_Disabled'
        {
            Name        = 'XboxNetApiSvc'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }
    }
}
xoap-kiosk-config-w11-24h2 -OutputPath 'C:\DSC\xoap-kiosk-config-w11-24h2'
