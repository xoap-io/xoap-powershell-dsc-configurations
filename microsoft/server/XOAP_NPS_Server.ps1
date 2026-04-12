# DSC Configuration: XOAP_NPS_Server
# Purpose: Configures Windows Network Policy Server (NPS/RADIUS) for 802.1x and VPN authentication.
Configuration 'XOAP_NPS_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_NPS_Server'
    {
        # --- Windows Features ---
        WindowsFeature 'NPAS'
        {
            Name   = 'NPAS'
            Ensure = 'Present'
        }

        WindowsFeature 'RSAT_NPAS'
        {
            Name   = 'RSAT-NPAS'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'IAS'
        {
            Name        = 'IAS'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Registry: NPS Security Settings ---
        Registry 'NPS_LogAccountingRequests'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy'
            Ensure    = 'Present'
            ValueName = 'Allow MS-CHAP v2'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'NPS_DisableMSCHAPv1'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy'
            Ensure    = 'Present'
            ValueName = 'Allow MS-CHAP'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'NPS_DisablePAP'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy'
            Ensure    = 'Present'
            ValueName = 'Allow PAP'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- File: NPS Log Directory ---
        File 'NPSLogDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\System32\LogFiles\NPS'
        }
    }
}
XOAP_NPS_Server -OutputPath 'C:\DSC\XOAP_NPS_Server'
