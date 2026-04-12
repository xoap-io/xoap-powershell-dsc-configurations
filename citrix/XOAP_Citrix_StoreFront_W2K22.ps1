# DSC Configuration: XOAP_Citrix_StoreFront_W2K22
# Purpose: Configures Citrix StoreFront service and IIS prerequisites on Windows Server 2022.
Configuration 'XOAP_Citrix_StoreFront_W2K22'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Citrix_StoreFront_W2K22'
    {
        # --- Windows Features: IIS and .NET Prerequisites ---
        WindowsFeature 'IIS'
        {
            Name   = 'Web-Server'
            Ensure = 'Present'
        }

        WindowsFeature 'IIS_MgmtConsole'
        {
            Name   = 'Web-Mgmt-Console'
            Ensure = 'Present'
        }

        WindowsFeature 'IIS_ScriptingTools'
        {
            Name   = 'Web-Scripting-Tools'
            Ensure = 'Present'
        }

        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Features'
            Ensure = 'Present'
        }

        WindowsFeature 'NetFramework45_ASPNET'
        {
            Name   = 'Net-Framework-45-ASPNET'
            Ensure = 'Present'
        }

        # --- Services: Citrix StoreFront ---
        Service 'CitrixConfigReplication'
        {
            Name        = 'CitrixConfigurationReplication'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'CitrixClusterService'
        {
            Name        = 'CitrixClusterService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'CitrixPeerResolution'
        {
            Name        = 'CitrixPeerResolutionService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'IIS_W3SVC'
        {
            Name        = 'W3SVC'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Registry: StoreFront HTTPS enforcement ---
        Registry 'StoreFront_UseHttps'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\DeliveryServices\StoreFront'
            Ensure    = 'Present'
            ValueName = 'UseHttps'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'StoreFront_TokenLifetime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\DeliveryServices\StoreFront'
            Ensure    = 'Present'
            ValueName = 'AuthenticationTokenLifetime'
            ValueType = 'Dword'
            ValueData = '3600'
        }
    }
}
XOAP_Citrix_StoreFront_W2K22 -OutputPath 'C:\DSC\XOAP_Citrix_StoreFront_W2K22'
