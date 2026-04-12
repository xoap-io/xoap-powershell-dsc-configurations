# DSC Configuration: XOAP_Debloat_W11_24H2_Taskbar_UI
# Purpose: Disables Widgets, lock screen tips, consumer content suggestions, and Microsoft Edge first-run experience for Windows 11 24H2.
Configuration 'XOAP_Debloat_W11_24H2_Taskbar_UI'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node 'XOAP_Debloat_W11_24H2_Taskbar_UI'
    {
        # --- Widgets ---
        Registry 'Widgets_Disable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh'
            Ensure    = 'Present'
            ValueName = 'AllowNewsAndInterests'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Consumer Content & Suggestions ---
        Registry 'Suggestions_DisableWindowsConsumer'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Suggestions_DisableThirdParty'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableThirdPartySuggestions'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Suggestions_DisableSoftLanding'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableSoftLanding'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Lock Screen ---
        Registry 'LockScreen_DisableTips'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'LockScreen_DisableSpotlight'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure    = 'Present'
            ValueName = 'DisableWindowsSpotlightFeatures'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Edge First-Run ---
        Registry 'Edge_DisableFirstRun'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure    = 'Present'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_Debloat_W11_24H2_Taskbar_UI -OutputPath 'C:\DSC\XOAP_Debloat_W11_24H2_Taskbar_UI'
