# DSC Configuration: XOAP_Debloat_W11_24H2_UserSettings
# Purpose: Applies per-user HKCU settings to all user profiles (including Default User) using UserRegistryDSC — file extensions, hidden files, dark mode, taskbar cleanup, advertising ID, and telemetry opt-out for Windows 11 24H2.
Configuration 'XOAP_Debloat_W11_24H2_UserSettings'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'UserRegistryDSC' -ModuleVersion '0.1.3'

    Node 'XOAP_Debloat_W11_24H2_UserSettings'
    {
        # --- File Explorer: Show Extensions & Hidden Files ---
        UserRegistry 'FileExt_Show'
        {
            Key       = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'HideFileExt'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        UserRegistry 'HiddenFiles_Show'
        {
            Key       = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'Hidden'
            ValueType = 'DWORD'
            ValueData = '1'
        }

        # --- Taskbar: Remove Chat and Copilot Buttons ---
        UserRegistry 'Taskbar_DisableChat'
        {
            Key       = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'TaskbarMn'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        UserRegistry 'Taskbar_DisableCopilotButton'
        {
            Key       = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName = 'ShowCopilotButton'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # --- Dark Mode ---
        UserRegistry 'DarkMode_Apps'
        {
            Key       = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
            ValueName = 'AppsUseLightTheme'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        UserRegistry 'DarkMode_System'
        {
            Key       = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize'
            ValueName = 'SystemUsesLightTheme'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # --- Per-User Advertising ID ---
        UserRegistry 'Advertising_DisableID'
        {
            Key       = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            ValueName = 'Enabled'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # --- Per-User Inking & Typing Personalization ---
        UserRegistry 'Telemetry_DisableInkingTyping'
        {
            Key       = 'HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC'
            ValueName = 'Enabled'
            ValueType = 'DWORD'
            ValueData = '0'
        }
    }
}
XOAP_Debloat_W11_24H2_UserSettings -OutputPath 'C:\DSC\XOAP_Debloat_W11_24H2_UserSettings'
