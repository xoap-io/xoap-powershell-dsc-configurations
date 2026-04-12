# DSC Configuration: XOAP_Debloat_W11_24H2_System
# Purpose: System-level optimizations — disables fast startup, prevents auto-reboot with logged-on users, disables AutoPlay and snap assist flyout for Windows 11 24H2.
Configuration 'XOAP_Debloat_W11_24H2_System'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node 'XOAP_Debloat_W11_24H2_System'
    {
        # --- Fast Startup ---
        Registry 'FastStartup_Disable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
            Ensure    = 'Present'
            ValueName = 'HiberbootEnabled'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Windows Update Reboot Behavior ---
        Registry 'WU_NoAutoReboot'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure    = 'Present'
            ValueName = 'NoAutoRebootWithLoggedOnUsers'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Application Compatibility ---
        Registry 'AppCompat_DisableInventory'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            Ensure    = 'Present'
            ValueName = 'DisableInventory'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- AutoPlay ---
        Registry 'AutoPlay_Disable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            Ensure    = 'Present'
            ValueName = 'NoDriveTypeAutoRun'
            ValueType = 'Dword'
            ValueData = '255'
        }

        # --- Snap Assist ---
        Registry 'Snap_DisableAssistFlyout'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            Ensure    = 'Present'
            ValueName = 'EnableSnapAssistFlyout'
            ValueType = 'Dword'
            ValueData = '0'
        }
    }
}
XOAP_Debloat_W11_24H2_System -OutputPath 'C:\DSC\XOAP_Debloat_W11_24H2_System'
