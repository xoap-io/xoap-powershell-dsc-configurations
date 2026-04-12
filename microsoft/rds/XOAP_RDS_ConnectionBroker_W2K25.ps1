# DSC Configuration: XOAP_RDS_ConnectionBroker_W2K25
# Purpose: Configures Remote Desktop Services Connection Broker on Windows Server 2025.
Configuration 'XOAP_RDS_ConnectionBroker_W2K25'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_RDS_ConnectionBroker_W2K25'
    {
        # --- Windows Features: Connection Broker ---
        WindowsFeature 'RDS_ConnectionBroker'
        {
            Name   = 'RDS-Connection-Broker'
            Ensure = 'Present'
        }

        WindowsFeature 'RSAT_RDS_ConnectionBroker'
        {
            Name   = 'RSAT-RDS-Connection-Broker'
            Ensure = 'Present'
        }

        WindowsFeature 'RDS_Licensing'
        {
            Name   = 'RDS-Licensing'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'Tssdis'
        {
            Name        = 'Tssdis'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'SessionEnv'
        {
            Name        = 'SessionEnv'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'TermService'
        {
            Name        = 'TermService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Registry: Connection Broker Settings ---
        Registry 'RDCBroker_LicensingMode'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'LicensingMode'
            ValueType = 'Dword'
            ValueData = '4'
        }

        Registry 'RDCBroker_NLA_Required'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'UserAuthentication'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'RDCBroker_EncryptionLevel'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'Dword'
            ValueData = '3'
        }

        Registry 'RDCBroker_SecurityLayer'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'SecurityLayer'
            ValueType = 'Dword'
            ValueData = '2'
        }
    }
}
XOAP_RDS_ConnectionBroker_W2K25 -OutputPath 'C:\DSC\XOAP_RDS_ConnectionBroker_W2K25'
