# DSC Configuration: xoap-w2k25-packaging-workstation-vdi
# Purpose: XOAP W2K25 server VDI golden image packaging workstation configuration.
Configuration 'xoap-w2k25-packaging-workstation-vdi'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-w2k25-packaging-workstation-vdi'
    {
        # --- Windows Features ---
        WindowsFeature 'RSAT_AD'
        {
            Name   = 'RSAT-AD-Tools'
            Ensure = 'Present'
        }

        WindowsFeature 'TelnetClient'
        {
            Name   = 'Telnet-Client'
            Ensure = 'Present'
        }

        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Features'
            Ensure = 'Present'
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

        # --- Registry: Disable SMB over QUIC During Packaging ---
        Registry 'DisableSMBQUIC'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure    = 'Present'
            ValueName = 'EnableSMBQUIC'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: LSA PPL (build phase — value 1) ---
        Registry 'LSA_RunAsPPL'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure    = 'Present'
            ValueName = 'RunAsPPL'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Disable Windows Installer elevation ---
        Registry 'AlwaysInstallElevated_HKLM'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
            Ensure    = 'Present'
            ValueName = 'AlwaysInstallElevated'
            ValueType = 'Dword'
            ValueData = '0'
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

        # --- Registry: Disable Lock Screen for VDI ---
        Registry 'DisableLockScreen'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            Ensure    = 'Present'
            ValueName = 'NoLockScreen'
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
xoap-w2k25-packaging-workstation-vdi -OutputPath 'C:\DSC\xoap-w2k25-packaging-workstation-vdi'
