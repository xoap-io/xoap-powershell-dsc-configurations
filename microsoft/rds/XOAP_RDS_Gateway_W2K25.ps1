# DSC Configuration: XOAP_RDS_Gateway_W2K25
# Purpose: Configures Remote Desktop Services Gateway on Windows Server 2025.
Configuration 'XOAP_RDS_Gateway_W2K25'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_RDS_Gateway_W2K25'
    {
        # --- Windows Features: RDS Gateway ---
        WindowsFeature 'RDS_Gateway'
        {
            Name   = 'RDS-Gateway'
            Ensure = 'Present'
        }

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

        WindowsFeature 'RDS_Licensing'
        {
            Name   = 'RDS-Licensing'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'TSGateway'
        {
            Name        = 'TSGateway'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'W3SVC'
        {
            Name        = 'W3SVC'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Registry: Gateway Security Settings ---
        Registry 'RDGateway_NLA_Required'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'UserAuthentication'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'RDGateway_EncryptionLevel'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'Dword'
            ValueData = '3'
        }

        Registry 'RDGateway_SecurityLayer'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'SecurityLayer'
            ValueType = 'Dword'
            ValueData = '2'
        }

        # --- Registry: W2K25-specific TLS 1.3 for RD Gateway ---
        Registry 'TLS13_Server_Enabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_RDS_Gateway_W2K25 -OutputPath 'C:\DSC\XOAP_RDS_Gateway_W2K25'
