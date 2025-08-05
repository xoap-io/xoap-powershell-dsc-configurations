Configuration 'XOAP_W2K22_2009_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

    Node 'XOAP_W2K22_2009_Citrix_Optimizer'
    {
        File 'XOAP-Folder'
        {
            Type = 'Directory'
            Ensure = 'Present'
            DestinationPath = 'C:\XOAP'
        }

        # Optimize services
        $services = @(
            @{ Name = 'DPS'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'WdiServiceHost'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'WdiSystemHost'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'EFS'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'SharedAccess'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'SstpSvc'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'SysMain'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'WerSvc'; State = 'stopped'; StartupType = 'Disabled' },
            @{ Name = 'defragsvc'; State = 'stopped'; StartupType = 'Manual' }
        )
        foreach ($svc in $services) {
            Service $svc.Name {
                Name        = $svc.Name
                State       = $svc.State
                StartupType = $svc.StartupType
            }
        }

        # Optimize scheduled tasks
        $tasks = @(
            @{ TaskName = 'AnalyzeSystem'; TaskPath = '\Microsoft\Windows\Power Efficiency Diagnostics' },
            @{ TaskName = 'BfeOnServiceStartTypeChange'; TaskPath = '\Microsoft\Windows\Windows Filtering Platform' },
            @{ TaskName = 'Consolidator'; TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program' },
            @{ TaskName = 'CreateObjectTask'; TaskPath = '\Microsoft\Windows\CloudExperienceHost' },
            @{ TaskName = 'IndexerAutomaticMaintenance'; TaskPath = '\Microsoft\Windows\Shell' },
            @{ TaskName = 'MapsToastTask'; TaskPath = '\Microsoft\Windows\Maps' },
            @{ TaskName = 'Microsoft Compatibility Appraiser'; TaskPath = '\Microsoft\Windows\Application Experience' },
            @{ TaskName = 'Microsoft-Windows-DiskDiagnosticDataCollector'; TaskPath = '\Microsoft\Windows\DiskDiagnostic' },
            @{ TaskName = 'Microsoft-Windows-DiskDiagnosticResolver'; TaskPath = '\Microsoft\Windows\DiskDiagnostic' },
            @{ TaskName = 'MNO Metadata Parser'; TaskPath = '\Microsoft\Windows\Mobile Broadband Accounts' },
            @{ TaskName = 'MobilityManager'; TaskPath = '\Microsoft\Windows\Ras' },
            @{ TaskName = 'Notifications'; TaskPath = '\Microsoft\Windows\Location' },
            @{ TaskName = 'ProactiveScan'; TaskPath = '\Microsoft\Windows\CHKDSK' },
            @{ TaskName = 'ProcessMemoryDiagnosticEvents'; TaskPath = '\Microsoft\Windows\MemoryDiagnostic' },
            @{ TaskName = 'ProgramDataUpdater'; TaskPath = '\Microsoft\Windows\Application Experience' },
            @{ TaskName = 'Proxy'; TaskPath = '\Microsoft\Windows\Autochk' },
            @{ TaskName = 'QueueReporting'; TaskPath = '\Microsoft\Windows\Windows Error Reporting' },
            @{ TaskName = 'RegIdleBackup'; TaskPath = '\Microsoft\Windows\Registry' },
            @{ TaskName = 'ResolutionHost'; TaskPath = '\Microsoft\Windows\WDI' },
            @{ TaskName = 'RunFullMemoryDiagnostic'; TaskPath = '\Microsoft\Windows\MemoryDiagnostic' },
            @{ TaskName = 'Scheduled'; TaskPath = '\Microsoft\Windows\Diagnosis' },
            @{ TaskName = 'ScheduledDefrag'; TaskPath = '\Microsoft\Windows\Defrag' },
            @{ TaskName = 'ServerManager'; TaskPath = '\Microsoft\Windows\Server Manager' },
            @{ TaskName = 'StartComponentCleanup'; TaskPath = '\Microsoft\Windows\Servicing' },
            @{ TaskName = 'StartupAppTask'; TaskPath = '\Microsoft\Windows\Application Experience' },
            @{ TaskName = 'TPM-Maintenance'; TaskPath = '\Microsoft\Windows\TPM' },
            @{ TaskName = 'UninstallDeviceTask'; TaskPath = '\Microsoft\Windows\Bluetooth' },
            @{ TaskName = 'UPnPHostConfig'; TaskPath = '\Microsoft\Windows\UPnP' },
            @{ TaskName = 'UsbCeip'; TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program' },
            @{ TaskName = 'VerifyWinRE'; TaskPath = '\Microsoft\Windows\RecoveryEnvironment' },
            @{ TaskName = 'Windows Defender Cache Maintenance'; TaskPath = '\Microsoft\Windows\Windows Defender' },
            @{ TaskName = 'Windows Defender Cleanup'; TaskPath = '\Microsoft\Windows\Windows Defender' },
            @{ TaskName = 'Windows Defender Scheduled Scan'; TaskPath = '\Microsoft\Windows\Windows Defender' },
            @{ TaskName = 'Windows Defender Verification'; TaskPath = '\Microsoft\Windows\Windows Defender' },
            @{ TaskName = 'UpdateLibrary'; TaskPath = '\Microsoft\Windows\Windows Media Sharing' },
            @{ TaskName = 'WinSAT'; TaskPath = '\Microsoft\Windows\Maintenance' },
            @{ TaskName = 'Recovery-Check'; TaskPath = '\Microsoft\Windows\Workplace Join' }
        )
        foreach ($task in $tasks) {
            ScheduledTask $task.TaskName {
                TaskName   = $task.TaskName
                TaskPath   = $task.TaskPath
                Enable     = $false
                Ensure     = 'Absent'
            }
        }

        # Ensures user app containers are deleted on logoff to improve privacy and reduce leftover firewall rules
        Registry 'DeleteUserAppContainersOnLogoff' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Disables automatic layout adjustments for desktop icons
        Registry 'EnableAutoLayout' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout'
            Ensure      = 'Present'
            ValueName   = 'EnableAutoLayout'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Disables boot optimization defragmentation
        Registry 'Enable' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction'
            Ensure      = 'Present'
            ValueName   = 'Enable'
            ValueType   = 'String'
            ValueData   = 'N'
        }

        # Disables default screensaver for all users
        Registry 'ScreenSaveActive' {
            Key         = 'HKEY_USERS\.DEFAULT\Control Panel\Desktop'
            Ensure      = 'Present'
            ValueName   = 'ScreenSaveActive'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Disables creation of crash dumps to save disk space
        Registry 'CrashDumpEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
            Ensure      = 'Present'
            ValueName   = 'CrashDumpEnabled'
            ValueType   = 'DWORD'
            ValueData   = 0
        }

        # Improves NTFS performance by disabling last access time updates
        Registry 'NtfsDisableLastAccessUpdate' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem'
            Ensure      = 'Present'
            ValueName   = 'NtfsDisableLastAccessUpdate'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Suppresses system error popups and enables automatic error logging
        Registry 'ErrorMode' {
            Key         = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows'
            Ensure      = 'Present'
            ValueName   = 'ErrorMode'
            ValueType   = 'DWORD'
            ValueData   = 2
        }

        # Disables automatic Windows Updates
        Registry 'NoAutoUpdate' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure      = 'Present'
            ValueName   = 'NoAutoUpdate'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
