Configuration 'XOAP_W11_24H2_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
    Import-DscResource -ModuleName 'XOAPAppxPackageDSC' -ModuleVersion '0.1.0'

    Node 'XOAP_W11_24H2_Citrix_Optimizer'
    {
        # Windows 11 24H2: All optimizations and hardening from 2009, plus 24H2-specific settings

        # Disable unnecessary services
        $services = @(
            'AJRouter',
            'ALG'
        )
        foreach ($svc in $services) {
            Service $svc {
                Name        = $svc
                State       = 'stopped'
                StartupType = 'Disabled'
            }
        }

        # Remove unwanted Appx packages
        $appxPackages = @('Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe')
        foreach ($pkg in $appxPackages) {
            cAppxProvisionedPackage $pkg {
                PackageName = $pkg
                Ensure = 'Absent'
            }
        }

        # Disable scheduled tasks
        $scheduledTasks = @(
            @{Name='AnalyzeSystem';Path='\Microsoft\Windows\Power Efficiency Diagnostics'}
        )
        foreach ($task in $scheduledTasks) {
            ScheduledTask $($task.Name) {
                TaskName = $task.Name
                TaskPath = $task.Path
                Enable   = $false
                Ensure   = 'Absent'
            }
        }

        # Ensures user app containers are deleted on logoff for improved security
        Registry 'DeleteUserAppContainersOnLogoff' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'Dword'
            ValueData   = '1'
        }

        # Enables SMB over QUIC for modern file sharing
        Registry 'EnableSMBOverQUIC' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableSMBQUIC'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Ensures Defender Tamper Protection is enabled
        Registry 'DefenderTamperProtection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
            Ensure      = 'Present'
            ValueName   = 'TamperProtection'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables TLS 1.3 for improved security
        Registry 'EnableTLS13' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Enables TLS 1.3 for server
        Registry 'EnableTLS13Server' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Requires SMB signing for all connections
        Registry 'RequireSMBSigning' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'RequireSecuritySignature'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables Remote Credential Guard for RDP
        Registry 'EnableRemoteCredentialGuard' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            Ensure      = 'Present'
            ValueName   = 'AllowProtectedCreds'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Sets HDX graphics mode to Thinwire Plus
        Registry 'HDXGraphicsMode' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics'
            Ensure      = 'Present'
            ValueName   = 'GraphicsMode'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables session reliability
        Registry 'SessionReliability' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\SessionReliability'
            Ensure      = 'Present'
            ValueName   = 'SessionReliabilityEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Enables auto client reconnect
        Registry 'AutoClientReconnect' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\AutoReconnect'
            Ensure      = 'Present'
            ValueName   = 'AutoReconnectEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables clipboard redirection
        Registry 'ClipboardRedirection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Clipboard'
            Ensure      = 'Present'
            ValueName   = 'ClipboardRedirectionEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables audio redirection
        Registry 'AudioRedirection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Audio'
            Ensure      = 'Present'
            ValueName   = 'AudioRedirectionEnabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Sets power plan to High Performance
        Registry 'PowerPlan' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        }

        # Enables LSA Protection
        Registry 'EnableLSAProtection' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure      = 'Present'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables Credential Guard
        Registry 'EnableCredentialGuard' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables UDP for HDX
        Registry 'HDXUDP' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics\Thinwire\UDP'
            Ensure      = 'Present'
            ValueName   = 'EnableUDP'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables TCPNoDelay for low latency
        Registry 'TCPNoDelay' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure      = 'Present'
            ValueName   = 'TCPNoDelay'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables LargeSystemCache
        Registry 'LargeSystemCache' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Ensure      = 'Present'
            ValueName   = 'LargeSystemCache'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Sets VDA log level to verbose
        Registry 'VDALogLevel' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Logging\VDA'
            Ensure      = 'Present'
            ValueName   = 'LogLevel'
            ValueType   = 'DWORD'
            ValueData   = '4'
        }

        # Enables StoreFront logging
        Registry 'StoreFrontLogging' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\StoreFront\Logging'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Enables Universal Print Server logging
        Registry 'UPSLogging' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\UPS\Logging'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        
        # Enables WEM Agent optimizations
        Registry 'WEMAgentOptimizations' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WEM\Agent\Optimizations'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
    }
}
