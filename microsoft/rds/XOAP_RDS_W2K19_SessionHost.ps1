# DSC Configuration: XOAP_RDS_W2K19_SessionHost
# Purpose: Configures a Windows Server 2019 Remote Desktop Session Host.
Configuration 'XOAP_RDS_W2K19_SessionHost'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC'     -ModuleVersion '2.10.0.0'

    Node 'XOAP_RDS_W2K19_SessionHost'
    {
        # --- Windows Features ---
        WindowsFeature 'RDS-RD-Server'
        {
            Name      = 'RDS-RD-Server'
            Ensure    = 'Present'
        }

        WindowsFeature 'RDS-Licensing'
        {
            Name      = 'RDS-Licensing'
            Ensure    = 'Present'
        }

        WindowsFeature 'RSAT-RDS-Tools'
        {
            Name      = 'RSAT-RDS-Tools'
            Ensure    = 'Present'
        }

        # --- Services ---
        Service 'TermService'
        {
            Name        = 'TermService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'UmRdpService'
        {
            Name        = 'UmRdpService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- NLA Required ---
        Registry 'RDS_NLA'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            Ensure    = 'Present'
            ValueName = 'UserAuthentication'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Encryption Level: High ---
        Registry 'RDS_EncryptionLevel'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            Ensure    = 'Present'
            ValueName = 'MinEncryptionLevel'
            ValueType = 'Dword'
            ValueData = '3'
        }

        # --- Security Layer: SSL/TLS ---
        Registry 'RDS_SecurityLayer'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            Ensure    = 'Present'
            ValueName = 'SecurityLayer'
            ValueType = 'Dword'
            ValueData = '2'
        }

        # --- Session limits ---
        Registry 'RDS_MaxIdleTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxIdleTime'
            ValueType = 'Dword'
            ValueData = '3600000'
        }

        Registry 'RDS_MaxDisconnectionTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxDisconnectionTime'
            ValueType = 'Dword'
            ValueData = '900000'
        }

        Registry 'RDS_MaxConnectionTime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'MaxConnectionTime'
            ValueType = 'Dword'
            ValueData = '28800000'
        }

        # --- Reconnect on session limits ---
        Registry 'RDS_fResetBroken'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fResetBroken'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Licensing mode: Per User ---
        Registry 'RDS_LicensingMode'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'LicensingMode'
            ValueType = 'Dword'
            ValueData = '4'
        }

        # --- Shadow permissions (full control with user's permission) ---
        Registry 'RDS_Shadow'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'Shadow'
            ValueType = 'Dword'
            ValueData = '2'
        }

        # --- Disable drive redirection ---
        Registry 'RDS_fDisableCdm'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableCdm'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Allow clipboard redirection ---
        Registry 'RDS_fDisableClip'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableClip'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Disable printer redirection (for security) ---
        Registry 'RDS_fDisableCpm'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableCpm'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- User rights: Allow log on through Remote Desktop Services ---
        UserRightsAssignment 'RDS_AllowLogon'
        {
            Policy   = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity = @('Administrators', 'Remote Desktop Users')
        }

        # --- User rights: Deny direct console logon for RDS users ---
        UserRightsAssignment 'RDS_DenyBatchLogon'
        {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = @('Guests')
        }

        # --- Keep alive ---
        Registry 'RDS_KeepAlive'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'KeepAliveEnable'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'RDS_KeepAliveInterval'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'KeepAliveInterval'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Audit: Remote Desktop logon events ---
        UserRightsAssignment 'RDS_RemoteInteractiveLogon'
        {
            Policy   = 'Allow_log_on_locally'
            Identity = @('Administrators')
        }
    }
}
XOAP_RDS_W2K19_SessionHost -OutputPath 'C:\DSC\XOAP_RDS_W2K19_SessionHost'
