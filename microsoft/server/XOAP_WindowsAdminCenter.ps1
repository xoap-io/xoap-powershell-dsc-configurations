# DSC Configuration: XOAP_WindowsAdminCenter
# Purpose: Configures Windows Admin Center prerequisites and service settings.
Configuration 'XOAP_WindowsAdminCenter'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_WindowsAdminCenter'
    {
        # --- Windows Features ---
        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Features'
            Ensure = 'Present'
        }

        WindowsFeature 'IIS_MgmtConsole'
        {
            Name   = 'Web-Mgmt-Console'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'ServerManagementGateway'
        {
            Name        = 'ServerManagementGateway'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- File: WAC Data Directory ---
        File 'WACDataDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\Server Management Experience'
        }

        # --- Registry: WAC Port Configuration (default 443) ---
        Registry 'WAC_Port'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManagementGateway'
            Ensure    = 'Present'
            ValueName = 'Port'
            ValueType = 'Dword'
            ValueData = '443'
        }

        Registry 'WAC_SslCertificateOption'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManagementGateway'
            Ensure    = 'Present'
            ValueName = 'SslCertificateOption'
            ValueType = 'String'
            ValueData = 'generate'
        }

        # --- Registry: TLS 1.2+ enforcement for WAC ---
        Registry 'TLS12_Enabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'TLS10_Disabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '0'
        }
    }
}
XOAP_WindowsAdminCenter -OutputPath 'C:\DSC\XOAP_WindowsAdminCenter'
