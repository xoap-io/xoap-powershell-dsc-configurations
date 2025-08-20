Configuration 'XOAP_W2K25_2009_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

    Node 'XOAP_W2K25_2009_Citrix_Optimizer'
    {
        # Services Section (optimized)
        $servicesToDisable = @(
            'AJRouter',
            'ALG',
            'BTAGService',
            'bthserv',
            'DPS',
            'WdiServiceHost',
            'WdiSystemHost',
            'MapsBroker',
            'EFS',
            'fdPHost',
            'FDResPub',
            'SharedAccess',
            'CscService',
            'SEMgrSvc',
            'SstpSvc',
            'SensrSvc',
            'shpamsvc',
            'SSDPSRV',
            'upnphost',
            'WMPNetworkSvc',
            'icssvc'
        )
        foreach ($svc in $servicesToDisable) {
            Service $svc {
                Name        = $svc
                State       = 'Stopped'
                StartupType = 'Disabled'
            }
        }

        # Scheduled Tasks Section (optimized)
        $scheduledTasks = @(
            @{Name='AnalyzeSystem';Path='\Microsoft\Windows\Power Efficiency Diagnostics'},
            @{Name='BfeOnServiceStartTypeChange';Path='\Microsoft\Windows\Windows Filtering Platform'},
            @{Name='Consolidator';Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='CreateObjectTask';Path='\Microsoft\Windows\CloudExperienceHost'},
            @{Name='IndexerAutomaticMaintenance';Path='\Microsoft\Windows\Shell'},
            @{Name='MapsToastTask';Path='\Microsoft\Windows\Maps'},
            @{Name='Microsoft Compatibility Appraiser';Path='\Microsoft\Windows\Application Experience'},
            @{Name='Microsoft-Windows-DiskDiagnosticDataCollector';Path='\Microsoft\Windows\DiskDiagnostic'},
            @{Name='Microsoft-Windows-DiskDiagnosticResolver';Path='\Microsoft\Windows\DiskDiagnostic'},
            @{Name='MNO Metadata Parser';Path='\Microsoft\Windows\Mobile Broadband Accounts'},
            @{Name='MobilityManager';Path='\Microsoft\Windows\Ras'},
            @{Name='Notifications';Path='\Microsoft\Windows\Location'},
            @{Name='ProactiveScan';Path='\Microsoft\Windows\CHKDSK'},
            @{Name='ProcessMemoryDiagnosticEvents';Path='\Microsoft\Windows\MemoryDiagnostic'},
            @{Name='ProgramDataUpdater';Path='\Microsoft\Windows\Application Experience'},
            @{Name='Proxy';Path='\Microsoft\Windows\Autochk'},
            @{Name='QueueReporting';Path='\Microsoft\Windows\Windows Error Reporting'},
            @{Name='RegIdleBackup';Path='\Microsoft\Windows\Registry'},
            @{Name='ResolutionHost';Path='\Microsoft\Windows\WDI'},
            @{Name='RunFullMemoryDiagnostic';Path='\Microsoft\Windows\MemoryDiagnostic'},
            @{Name='Scheduled';Path='\Microsoft\Windows\Diagnosis'},
            @{Name='ScheduledDefrag';Path='\Microsoft\Windows\Defrag'},
            @{Name='ServerManager';Path='\Microsoft\Windows\Server Manager'},
            @{Name='StartComponentCleanup';Path='\Microsoft\Windows\Servicing'},
            @{Name='StartupAppTask';Path='\Microsoft\Windows\Application Experience'},
            @{Name='TPM-Maintenance';Path='\Microsoft\Windows\TPM'},
            @{Name='UninstallDeviceTask';Path='\Microsoft\Windows\Bluetooth'},
            @{Name='UPnPHostConfig';Path='\Microsoft\Windows\UPnP'},
            @{Name='UsbCeip';Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='VerifyWinRE';Path='\Microsoft\Windows\RecoveryEnvironment'},
            @{Name='Windows Defender Cache Maintenance';Path='\Microsoft\Windows\Windows Defender'},
            @{Name='Windows Defender Cleanup';Path='\Microsoft\Windows\Windows Defender'},
            @{Name='Windows Defender Scheduled Scan';Path='\Microsoft\Windows\Windows Defender'},
            @{Name='Windows Defender Verification';Path='\Microsoft\Windows\Windows Defender'},
            @{Name='UpdateLibrary';Path='\Microsoft\Windows\Windows Media Sharing'},
            @{Name='WinSAT';Path='\Microsoft\Windows\Maintenance'},
            @{Name='Recovery-Check';Path='\Microsoft\Windows\Workplace Join'}
        )
        foreach ($task in $scheduledTasks) {
            ScheduledTask $($task.Name) {
                TaskName = $task.Name
                TaskPath = $task.Path
                Enable   = $false
                Ensure   = 'Absent'
            }
        }

        # Registry Settings Section
        Registry 'DeleteUserAppContainersOnLogoff' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'Dword'
            ValueData   = 1
        }

        # Enable Auto Layout
        Registry 'EnableAutoLayout' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout'
            Ensure      = 'Present'
            ValueName   = 'EnableAutoLayout'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Enable Boot Optimization
        Registry 'Enable' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction'
            Ensure      = 'Present'
            ValueName   = 'Enable'
            ValueType   = 'String'
            ValueData   = 'N'
        }

        # Enable Screen Saver
        Registry 'ScreenSaveActive' {
            Key         = 'HKEY_USERS\.DEFAULT\Control Panel\Desktop'
            Ensure      = 'Present'
            ValueName   = 'ScreenSaveActive'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Enable Crash Dump
        Registry 'CrashDumpEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
            Ensure      = 'Present'
            ValueName   = 'CrashDumpEnabled'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Enable Last Access Update
        Registry 'NtfsDisableLastAccessUpdate' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem'
            Ensure      = 'Present'
            ValueName   = 'NtfsDisableLastAccessUpdate'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Enable Error Mode
        Registry 'ErrorMode' {
            Key         = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows'
            Ensure      = 'Present'
            ValueName   = 'ErrorMode'
            ValueType   = 'DWORD'
            ValueData   = 2
        }

        # Enable Disk Timeout
        Registry 'TimeOutValue' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk'
            Ensure      = 'Present'
            ValueName   = 'TimeOutValue'
            ValueType   = 'DWORD'
            ValueData   = 0x000000C8
        }

        # Enable Automatic Updates
        Registry 'NoAutoUpdate' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure      = 'Present'
            ValueName   = 'NoAutoUpdate'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Windows Defender (disable if using 3rd party AV)
        Registry 'DisableDefender' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
            Ensure      = 'Present'
            ValueName   = 'DisableAntiSpyware'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Telemetry
        Registry 'Telemetry' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure      = 'Present'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # SMBv1 Disable
        Registry 'SMBv1' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'SMB1'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Remote Desktop - Restrict access
        Registry 'RDPTimeout' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
            Ensure      = 'Present'
            ValueName   = 'MaxIdleTime'
            ValueType   = 'DWORD'
            ValueData   = 1800000
        }

        # Power Plan - High Performance
        Registry 'PowerPlan' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' # High Performance GUID
        }

        # Event Log - Limit log size
        Registry 'ApplicationLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }

        # Event Log - Limit log size
        Registry 'SystemLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }

        # Network - TCP/IP tuning
        Registry 'TcpAutoTuning' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableTCPA'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Storage - Disable Storage Spaces Direct (if not used)
        Registry 'DisableS2D' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\S2D'
            Ensure      = 'Present'
            ValueName   = 'Start'
            ValueType   = 'DWORD'
            ValueData   = 4
        }

        # Security - Harden LSA
        Registry 'RunAsPPL' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure      = 'Present'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Security - Credential Guard
        Registry 'EnableVirtualizationBasedSecurity' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Security - Require Platform Security Features
        Registry 'RequirePlatformSecurityFeatures' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'RequirePlatformSecurityFeatures'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Windows Server 2025: Enable SMB over QUIC (if using)
        Registry 'EnableSMBOverQUIC' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableSMBQUIC'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Windows Server 2025: Enable Windows Defender Tamper Protection
        Registry 'TamperProtection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
            Ensure      = 'Present'
            ValueName   = 'TamperProtection'
            ValueType   = 'DWORD'
            ValueData   = 5
        }

        # Windows Server 2025: Enforce TLS 1.3 for Schannel
        Registry 'TLS13Enabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
            Ensure      = 'Present'
            ValueName   = 'Enabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Windows Server 2025: Harden SMB signing
        Registry 'RequireSecuritySignature' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'RequireSecuritySignature'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Windows Server 2025: Harden Remote Credential Guard
        Registry 'RemoteCredentialGuard' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            Ensure      = 'Present'
            ValueName   = 'AllowProtectedCreds'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}