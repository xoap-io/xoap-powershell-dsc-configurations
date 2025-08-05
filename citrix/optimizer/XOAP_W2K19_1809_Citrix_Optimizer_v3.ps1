# XOAP_W2K19_1809_Citrix_Optimizer.ps1 migrated to DSC v3
# This configuration uses the new DSC v3 syntax and best practices for maintainability and clarity.
# All registry resources include comments explaining their purpose.

Configuration XOAP_W2K19_1809_Citrix_Optimizer_v3 {
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

    Node localhost {
        File XOAP_Folder {
            Type = 'Directory'
            Ensure = 'Present'
            DestinationPath = 'C:\XOAP'
        }

        # Disable unnecessary services for Citrix optimization
        foreach ($svc in @(
            'DPS','WdiServiceHost','WdiSystemHost','EFS','SharedAccess','SstpSvc','SysMain','WerSvc')) {
            Service $svc {
                Name        = $svc
                State       = 'stopped'
                StartupType = 'Disabled'
            }
        }
        Service defragsvc {
            Name        = 'defragsvc'
            State       = 'stopped'
            StartupType = 'Manual'
        }

        # Remove unnecessary scheduled tasks
        $tasks = @(
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
        foreach ($task in $tasks) {
            ScheduledTask $($task.Name) {
                TaskName = $task.Name
                TaskPath = $task.Path
                Enable   = $false
                Ensure   = 'Absent'
            }
        }

        # Registry optimizations with comments
        # Ensures user app containers are deleted on logoff for improved security
        Registry DeleteUserAppContainersOnLogoff {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'Dword'
            ValueData   = '1'
        }
        # Disables automatic layout adjustments for desktop icons
        Registry EnableAutoLayout {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout'
            Ensure      = 'Present'
            ValueName   = 'EnableAutoLayout'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }
        # Disables boot optimization to reduce unnecessary disk activity
        Registry Enable {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction'
            Ensure      = 'Present'
            ValueName   = 'Enable'
            ValueType   = 'String'
            ValueData   = 'N'
        }
        # Disables screensaver for the default user profile
        Registry ScreenSaveActive {
            Key         = 'HKEY_USERS\.DEFAULT\Control Panel\Desktop'
            Ensure      = 'Present'
            ValueName   = 'ScreenSaveActive'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }
        # Disables crash dump creation to save disk space
        Registry CrashDumpEnabled {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
            Ensure      = 'Present'
            ValueName   = 'CrashDumpEnabled'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }
        # Disables NTFS last access update to improve disk performance
        Registry NtfsDisableLastAccessUpdate {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem'
            Ensure      = 'Present'
            ValueName   = 'NtfsDisableLastAccessUpdate'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
        # Sets error mode to suppress system error dialogs
        Registry ErrorMode {
            Key         = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows'
            Ensure      = 'Present'
            ValueName   = 'ErrorMode'
            ValueType   = 'DWORD'
            ValueData   = '2'
        }
        # Disables automatic Windows Updates for better control in Citrix environments
        Registry NoAutoUpdate {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure      = 'Present'
            ValueName   = 'NoAutoUpdate'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }
    }
}
