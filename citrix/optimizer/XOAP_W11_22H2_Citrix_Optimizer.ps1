Configuration 'XOAP_W11_22H2_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDSC'        -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'
    Import-DscResource -ModuleName 'NetworkingDsc'         -ModuleVersion '8.2.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC'     -ModuleVersion '2.10.0.0'

    Node 'XOAP_W11_22H2_Citrix_Optimizer'
    {
        # Windows 11 22H2: Citrix optimizer settings
        # Based on XOAP_W11_23H2_Citrix_Optimizer with 22H2-specific adjustments

        # Disable unnecessary services
        $services = @(
            'AJRouter',
            'ALG',
            'AppReadiness',
            'AppVClient',
            'bthserv',
            'diagnosticshub.standardcollector.service',
            'DiagTrack',
            'DPS',
            'DsmSvc',
            'EntAppSvc',
            'Fax',
            'ftpsvc',
            'HomeGroupListener',
            'HomeGroupProvider',
            'HvHost',
            'irmon',
            'lfsvc',
            'MapsBroker',
            'MessagingService',
            'NetTcpPortSharing',
            'PeerDistSvc',
            'PhoneSvc',
            'PrintNotify',
            'RasAuto',
            'RemoteRegistry',
            'RetailDemo',
            'RpcLocator',
            'SCardSvr',
            'SCPolicySvc',
            'SharedAccess',
            'stisvc',
            'TabletInputService',
            'UevAgentService',
            'WalletService',
            'wbengine',
            'WbioSrvc',
            'wcncsvc',
            'WerSvc',
            'wisvc',
            'WMPNetworkSvc',
            'WpcMonSvc',
            'WSearch',
            'XblAuthManager',
            'XblGameSave',
            'XboxNetApiSvc'
        )

        foreach ($svc in $services) {
            Service $svc {
                Name        = $svc
                State       = 'Stopped'
                StartupType = 'Disabled'
            }
        }

        # Disable scheduled tasks
        $scheduledTasks = @(
            @{Name='AnalyzeSystem';   Path='\Microsoft\Windows\Power Efficiency Diagnostics'},
            @{Name='Consolidator';    Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='KernelCeipTask';  Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='UsbCeip';         Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='Microsoft-Windows-DiskDiagnosticDataCollector'; Path='\Microsoft\Windows\DiskDiagnostic'},
            @{Name='GatherNetworkInfo'; Path='\Microsoft\Windows\NetTrace'},
            @{Name='QueueReporting';  Path='\Microsoft\Windows\Windows Error Reporting'}
        )

        foreach ($task in $scheduledTasks) {
            ScheduledTask $($task.Name) {
                TaskName = $task.Name
                TaskPath = $task.Path
                Enable   = $false
                Ensure   = 'Present'
            }
        }

        # --- Citrix-specific registry settings ---
        Registry 'HDXGraphicsMode' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics'
            Ensure    = 'Present'
            ValueName = 'GraphicsMode'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'SessionReliability' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\SessionReliability'
            Ensure    = 'Present'
            ValueName = 'SessionReliabilityEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'AutoClientReconnect' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\AutoReconnect'
            Ensure    = 'Present'
            ValueName = 'AutoReconnectEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'ClipboardRedirection' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Clipboard'
            Ensure    = 'Present'
            ValueName = 'ClipboardRedirectionEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'AudioRedirection' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Audio'
            Ensure    = 'Present'
            ValueName = 'AudioRedirectionEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'HDXUDP' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics\Thinwire\UDP'
            Ensure    = 'Present'
            ValueName = 'EnableUDP'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Performance optimizations ---
        Registry 'PowerPlan' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure    = 'Present'
            ValueName = 'ActivePowerScheme'
            ValueType = 'String'
            ValueData = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        }

        Registry 'TCPNoDelay' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure    = 'Present'
            ValueName = 'TCPNoDelay'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'LargeSystemCache' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Ensure    = 'Present'
            ValueName = 'LargeSystemCache'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Security ---
        Registry 'RequireSMBSigning' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure    = 'Present'
            ValueName = 'RequireSecuritySignature'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'EnableLSAProtection' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure    = 'Present'
            ValueName = 'RunAsPPL'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'EnableTLS13Client' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'EnableTLS13Server' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'DefenderTamperProtection' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
            Ensure    = 'Present'
            ValueName = 'TamperProtection'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'WEMAgentOptimizations' {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WEM\Agent\Optimizations'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'DeleteUserAppContainersOnLogoff' {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure    = 'Present'
            ValueName = 'DeleteUserAppContainersOnLogoff'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_W11_22H2_Citrix_Optimizer -OutputPath 'C:\DSC\XOAP_W11_22H2_Citrix_Optimizer'
