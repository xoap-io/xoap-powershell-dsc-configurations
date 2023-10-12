Configuration 'XOAP_W2k12R2_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

    Node 'XOAP_W2k12R2_Citrix_Optimizer'
    {
        File 'XOAP-Folder'
        {
            Type = 'Directory'
            Ensure = 'Present'
            DestinationPath = 'C:\XOAP'
        }

        Service 'ALG'
        {
        Name        = 'ALG'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'Browser'
        {
        Name        = 'Browser'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'DPS'
        {
        Name        = 'DPS'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'WdiServiceHost'
        {
        Name        = 'WdiServiceHost'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'WdiSystemHost'
        {
        Name        = 'WdiSystemHost'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'EFS'
        {
        Name        = 'EFS'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'fdPHost'
        {
        Name        = 'fdPHost'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'FDResPub'
        {
        Name        = 'FDResPub'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'SharedAccess'
        {
        Name        = 'SharedAccess'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'SSDPSRV'
        {
        Name        = 'SSDPSRV'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'upnphost'
        {
        Name        = 'upnphost'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'SysMain'
        {
        Name        = 'SysMain'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'Themes'
        {
        Name        = 'Themes'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'WerSvc'
        {
        Name        = 'WerSvc'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'WSearch'
        {
        Name        = 'WSearch'
        State       = 'stopped'
        StartupType = 'Disabled'
        }

        Service 'DiagTrack'
        {
        Name        = 'DiagTrack'
        State       = 'stopped'
        StartupType = 'Automatic'
        }

        Service 'defragsvc'
        {
        Name        = 'defragsvc'
        State       = 'stopped'
        StartupType = 'Manual'
        }

        Service 'ShellHWDetection'
        {
        Name        = 'ShellHWDetection'
        State       = 'stopped'
        StartupType = 'Automatic'
        }

        ScheduledTask 'AnalyzeSystem'
        {
        TaskName            = 'AnalyzeSystem'
        TaskPath            = '\Microsoft\Windows\Power Efficiency Diagnostics'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'AitAgent'
        {
        TaskName            = 'AitAgent'
        TaskPath            = '\Microsoft\Windows\Application Experience'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'BfeOnServiceStartTypeChange'
        {
        TaskName            = 'BfeOnServiceStartTypeChange'
        TaskPath            = '\Microsoft\Windows\Windows Filtering Platform'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'Consolidator'
        {
        TaskName            = 'Consolidator'
        TaskPath            = '\Microsoft\Windows\Customer Experience Improvement Program'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ServerCeipAssistant'
        {
        TaskName            = 'ServerCeipAssistant'
        TaskPath            = '\Microsoft\Windows\Customer Experience Improvement Program\Server'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ServerRoleCollector-RunOnce'
        {
        TaskName            = 'ServerRoleCollector-RunOnce'
        TaskPath            = '\Microsoft\Windows\Customer Experience Improvement Program\Server'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'Microsoft-Windows-DiskDiagnosticDataCollector'
        {
        TaskName            = 'Microsoft-Windows-DiskDiagnosticDataCollector'
        TaskPath            = '\Microsoft\Windows\DiskDiagnostic'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'Microsoft-Windows-DiskDiagnosticResolver'
        {
        TaskName            = 'Microsoft-Windows-DiskDiagnosticResolver'
        TaskPath            = '\Microsoft\Windows\DiskDiagnostic'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'KernelCeipTask'
        {
        TaskName            = 'KernelCeipTask'
        TaskPath            = '\Microsoft\Windows\Customer Experience Improvement Program'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ProactiveScan'
        {
        TaskName            = 'ProactiveScan'
        TaskPath            = '\Microsoft\Windows\CHKDSK'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ProgramDataUpdater'
        {
        TaskName            = 'ProgramDataUpdater'
        TaskPath            = '\Microsoft\Windows\Application Experience'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'Proxy'
        {
        TaskName            = 'Proxy'
        TaskPath            = '\Microsoft\Windows\Autochk'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'RegIdleBackup'
        {
        TaskName            = 'RegIdleBackup'
        TaskPath            = '\Microsoft\Windows\Registry'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ResolutionHost'
        {
        TaskName            = 'ResolutionHost'
        TaskPath            = '\Microsoft\Windows\WDI'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ScheduledDefrag'
        {
        TaskName            = 'ScheduledDefrag'
        TaskPath            = '\Microsoft\Windows\Defrag'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'ServerManager'
        {
        TaskName            = 'ServerManager'
        TaskPath            = '\Microsoft\Windows\Server Manager'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'StartComponentCleanup'
        {
        TaskName            = 'StartComponentCleanup'
        TaskPath            = '\Microsoft\Windows\Servicing'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'UsbCeip'
        {
        TaskName            = 'UsbCeip'
        TaskPath            = '\Microsoft\Windows\Customer Experience Improvement Program'
        Enable              = $false
        Ensure              = 'Absent'
        }

        ScheduledTask 'QueueReporting'
        {
        TaskName            = 'QueueReporting'
        TaskPath            = '\Microsoft\Windows\Windows Error Reporting'
        Enable              = $false
        Ensure              = 'Absent'
        }

        Registry 'EnableAutoLayout'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout'
        Ensure      = 'Present'
        ValueName   = 'EnableAutoLayout'
        ValueType   = 'DWORD'
        ValueData   = '0'
        }

        Registry 'Enable'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction'
        Ensure      = 'Present'
        ValueName   = 'Enable'
        ValueType   = 'String'
        ValueData   = 'N'
        }

        Registry 'ScreenSaveActive'
        {
        Key         = 'HKEY_USERS\.DEFAULT\Control Panel\Desktop'
        Ensure      = 'Present'
        ValueName   = 'ScreenSaveActive'
        ValueType   = 'DWORD'
        ValueData   = '0'
        }

        Registry 'CrashDumpEnabled'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
        Ensure      = 'Present'
        ValueName   = 'CrashDumpEnabled'
        ValueType   = 'DWORD'
        ValueData   = '0'
        }

        Registry 'NtfsDisableLastAccessUpdate'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem'
        Ensure      = 'Present'
        ValueName   = 'NtfsDisableLastAccessUpdate'
        ValueType   = 'DWORD'
        ValueData   = '1'
        }

        Registry 'EnableFirstLogonAnimation'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Ensure      = 'Present'
        ValueName   = 'EnableFirstLogonAnimation'
        ValueType   = 'DWORD'
        ValueData   = '0'
        }

        Registry 'ErrorMode'
        {
        Key         = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows'
        Ensure      = 'Present'
        ValueName   = 'ErrorMode'
        ValueType   = 'DWORD'
        ValueData   = '2'
        }

        Registry 'TimeOutValue'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk'
        Ensure      = 'Present'
        ValueName   = 'TimeOutValue'
        ValueType   = 'DWORD'
        ValueData   = '3c'
        }

        Registry 'NoAutoUpdate'
        {
        Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Ensure      = 'Present'
        ValueName   = 'NoAutoUpdate'
        ValueType   = 'DWORD'
        ValueData   = '1'
        }
    }
}
