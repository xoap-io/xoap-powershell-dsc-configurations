# DSC Configuration: xoap-w2k25-packaging-workstation
# Purpose: XOAP W2K25 server golden image packaging workstation configuration.
Configuration 'xoap-w2k25-packaging-workstation'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'xoap-w2k25-packaging-workstation'
    {
        # --- Windows Features ---
        WindowsFeature 'IIS'
        {
            Name   = 'Web-Server'
            Ensure = 'Present'
        }

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
xoap-w2k25-packaging-workstation -OutputPath 'C:\DSC\xoap-w2k25-packaging-workstation'
