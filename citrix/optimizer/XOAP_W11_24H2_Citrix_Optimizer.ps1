Configuration 'XOAP_W11_24H2_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
    Import-DscResource -ModuleName 'XOAPAppxPackageDSC' -ModuleVersion '0.1.0'

    Node 'XOAP_W11_24H2_Citrix_Optimizer'
    {
        # Windows 11 24H2: All optimizations and hardening from 2009, plus 24H2-specific settings
        # Disable unnecessary services
        Service 'AJRouter' { Name = 'AJRouter'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'ALG' { Name = 'ALG'; State = 'stopped'; StartupType = 'Disabled' }
        # ...existing code for disabling services...

        # Remove unwanted Appx packages
        cAppxProvisionedPackage 'Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        # ...existing code for removing Appx packages...

        # Disable scheduled tasks
        ScheduledTask 'AnalyzeSystem' { TaskName = 'AnalyzeSystem'; TaskPath = '\Microsoft\Windows\Power Efficiency Diagnostics'; Enable = $false; Ensure = 'Absent' }
        # ...existing code for disabling scheduled tasks...

        # Registry optimizations
        Registry 'DeleteUserAppContainersOnLogoff' # Ensures user app containers are deleted on logoff for improved security
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'Dword'
            ValueData   = '1'
        }
        # ...existing registry optimizations with comments...

        # Windows 11 24H2-specific optimizations
        # Example: Enable SMB over QUIC (if applicable)
        Registry 'EnableSMBOverQUIC' # Enables SMB over QUIC for modern file sharing
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableSMBQUIC'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Example: Harden Windows Defender settings
        Registry 'DefenderTamperProtection' # Ensures Defender Tamper Protection is enabled
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
            Ensure      = 'Present'
            ValueName   = 'TamperProtection'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Example: Enable TLS 1.3
        Registry 'EnableTLS13' # Enables TLS 1.3 for improved security
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'EnableTLS13Server' # Enables TLS 1.3 for server
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Example: Harden SMB signing
        Registry 'RequireSMBSigning' # Requires SMB signing for all connections
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'RequireSecuritySignature'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Example: Enable Remote Credential Guard
        Registry 'EnableRemoteCredentialGuard' # Enables Remote Credential Guard for RDP
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            Ensure      = 'Present'
            ValueName   = 'AllowProtectedCreds'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Citrix HDX graphics optimization (Thinwire/H.264)
        Registry 'HDXGraphicsMode' # Sets HDX graphics mode to Thinwire Plus
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics'
            Ensure      = 'Present'
            ValueName   = 'GraphicsMode'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Session Reliability and Auto Client Reconnect
        Registry 'SessionReliability' # Enables session reliability
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\SessionReliability'
            Ensure      = 'Present'
            ValueName   = 'SessionReliabilityEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'AutoClientReconnect' # Enables auto client reconnect
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\AutoReconnect'
            Ensure      = 'Present'
            ValueName   = 'AutoReconnectEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Clipboard and audio redirection optimization
        Registry 'ClipboardRedirection' # Enables clipboard redirection
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Clipboard'
            Ensure      = 'Present'
            ValueName   = 'ClipboardRedirectionEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'AudioRedirection' # Enables audio redirection
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Audio'
            Ensure      = 'Present'
            ValueName   = 'AudioRedirectionEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Power plan optimization
        Registry 'PowerPlan' # Sets power plan to High Performance
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        }

        # Security hardening: Credential Guard, LSA Protection
        Registry 'EnableLSAProtection' # Enables LSA Protection
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure      = 'Present'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'EnableCredentialGuard' # Enables Credential Guard
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Network optimizations: Enable UDP for HDX, TCP/IP tweaks
        Registry 'HDXUDP' # Enables UDP for HDX
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics\Thinwire\UDP'
            Ensure      = 'Present'
            ValueName   = 'EnableUDP'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'TCPNoDelay' # Enables TCPNoDelay for low latency
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure      = 'Present'
            ValueName   = 'TCPNoDelay'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'LargeSystemCache' # Enables LargeSystemCache
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Ensure      = 'Present'
            ValueName   = 'LargeSystemCache'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Logging: Enable Citrix VDA logging
        Registry 'VDALogLevel' # Sets VDA log level to verbose
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Logging\VDA'
            Ensure      = 'Present'
            ValueName   = 'LogLevel'
            ValueType   = 'DWORD'
            ValueData   = '4'
        }
        # StoreFront and UPS logging
        Registry 'StoreFrontLogging' # Enables StoreFront logging
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\StoreFront\Logging'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        Registry 'UPSLogging' # Enables Universal Print Server logging
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UPS\Logging'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # WEM Agent optimizations
        Registry 'WEMAgentOptimizations' # Enables WEM Agent optimizations
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WEM\Agent\Optimizations'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
    }
}
