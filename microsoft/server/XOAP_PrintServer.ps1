# DSC Configuration: XOAP_PrintServer
# Purpose: Configures Windows Print Server with spooler hardening and IIS-based IPP printing.
Configuration 'XOAP_PrintServer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_PrintServer'
    {
        # --- Windows Features ---
        WindowsFeature 'PrintServices'
        {
            Name   = 'Print-Services'
            Ensure = 'Present'
        }

        WindowsFeature 'PrintServer'
        {
            Name   = 'Print-Server'
            Ensure = 'Present'
        }

        WindowsFeature 'PrintInternet'
        {
            Name   = 'Print-Internet'
            Ensure = 'Present'
        }

        WindowsFeature 'PrintLPD'
        {
            Name   = 'Print-LPD-Service'
            Ensure = 'Absent'
        }

        # --- Services ---
        Service 'Spooler'
        {
            Name        = 'Spooler'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'PrintNotify'
        {
            Name        = 'PrintNotify'
            State       = 'Running'
            StartupType = 'Manual'
        }

        # --- Registry: Spooler Hardening (CVE-2021-34527 / PrintNightmare) ---
        Registry 'Spooler_NoRemotePointAndPrint'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Ensure    = 'Present'
            ValueName = 'NoWarningNoElevationOnInstall'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Spooler_UpdatePromptSettings'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Ensure    = 'Present'
            ValueName = 'UpdatePromptSettings'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Spooler_RestrictDriverInstallationToAdministrators'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Ensure    = 'Present'
            ValueName = 'RestrictDriverInstallationToAdministrators'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: Disable Spooler RPC over TCP ---
        Registry 'Spooler_RpcTcpPort'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            Ensure    = 'Present'
            ValueName = 'RegisterSpoolerRemoteRpcEndPoint'
            ValueType = 'Dword'
            ValueData = '2'
        }

        # --- File: Spool Directory ---
        File 'SpoolDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\System32\spool\PRINTERS'
        }
    }
}
XOAP_PrintServer -OutputPath 'C:\DSC\XOAP_PrintServer'
