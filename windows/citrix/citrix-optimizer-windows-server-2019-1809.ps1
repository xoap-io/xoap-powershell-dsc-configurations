Configuration 'citrix-optimizer-windows-server-2019-1809'
{
Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
Import-DSCResource -ModuleName "AuditPolicyDSC"
Import-DSCResource -ModuleName "SecurityPolicyDSC"
Import-DSCResource -ModuleName "DSCR_AppxPackage"
Import-DSCResource -ModuleName "ComputerManagementDsc"

    Node 'citrix-optimizer-windows-server-2019-1809'
    {
        Service "AJRouter"
        {
        Name        = "AJRouter"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "ALG"
        {
        Name        = "ALG"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "BTAGService"
        {
        Name        = "BTAGService"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "bthserv"
        {
        Name        = "bthserv"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "DPS"
        {
        Name        = "DPS"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WdiServiceHost"
        {
        Name        = "WdiServiceHost"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WdiSystemHost"
        {
        Name        = "WdiSystemHost"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "MapsBroker"
        {
        Name        = "MapsBroker"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "EFS"
        {
        Name        = "EFS"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "fdPHost"
        {
        Name        = "fdPHost"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "FDResPub"
        {
        Name        = "FDResPub"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SharedAccess"
        {
        Name        = "SharedAccess"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "CscService"
        {
        Name        = "CscService"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "CSC"
        {
        Name        = "CSC"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SEMgrSvc"
        {
        Name        = "SEMgrSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SstpSvc"
        {
        Name        = "SstpSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SensrSvc"
        {
        Name        = "SensrSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "shpamsvc"
        {
        Name        = "shpamsvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SSDPSRV"
        {
        Name        = "SSDPSRV"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "upnphost"
        {
        Name        = "upnphost"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WMPNetworkSvc"
        {
        Name        = "WMPNetworkSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "icssvc"
        {
        Name        = "icssvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SysMain"
        {
        Name        = "SysMain"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "Themes"
        {
        Name        = "Themes"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WerSvc"
        {
        Name        = "WerSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WSearch"
        {
        Name        = "WSearch"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "DiagTrack"
        {
        Name        = "DiagTrack"
        State       = "stopped"
        StartupType = "Automatic"
        }

        Service "defragsvc"
        {
        Name        = "defragsvc"
        State       = "stopped"
        StartupType = "Manual"
        }

        Service "ShellHWDetection"
        {
        Name        = "ShellHWDetection"
        State       = "stopped"
        StartupType = "Automatic"
        }

        ScheduledTask "AnalyzeSystem"
        {
        TaskName            = "AnalyzeSystem"
        TaskPath            = "\Microsoft\Windows\Power Efficiency Diagnostics"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "BfeOnServiceStartTypeChange"
        {
        TaskName            = "BfeOnServiceStartTypeChange"
        TaskPath            = "\Microsoft\Windows\Windows Filtering Platform"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Consolidator"
        {
        TaskName            = "Consolidator"
        TaskPath            = "\Microsoft\Windows\Customer Experience Improvement Program"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "CreateObjectTask"
        {
        TaskName            = "CreateObjectTask"
        TaskPath            = "\Microsoft\Windows\CloudExperienceHost"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "IndexerAutomaticMaintenance"
        {
        TaskName            = "IndexerAutomaticMaintenance"
        TaskPath            = "\Microsoft\Windows\Shell"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "MapsToastTask"
        {
        TaskName            = "MapsToastTask"
        TaskPath            = "\Microsoft\Windows\Maps"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Microsoft Compatibility Appraiser"
        {
        TaskName            = "Microsoft Compatibility Appraiser"
        TaskPath            = "\Microsoft\Windows\Application Experience"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Microsoft-Windows-DiskDiagnosticDataCollector"
        {
        TaskName            = "Microsoft-Windows-DiskDiagnosticDataCollector"
        TaskPath            = "\Microsoft\Windows\DiskDiagnostic"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Microsoft-Windows-DiskDiagnosticResolver"
        {
        TaskName            = "Microsoft-Windows-DiskDiagnosticResolver"
        TaskPath            = "\Microsoft\Windows\DiskDiagnostic"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "MNO Metadata Parser"
        {
        TaskName            = "MNO Metadata Parser"
        TaskPath            = "\Microsoft\Windows\Mobile Broadband Accounts"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "MobilityManager"
        {
        TaskName            = "MobilityManager"
        TaskPath            = "\Microsoft\Windows\Ras"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Notifications"
        {
        TaskName            = "Notifications"
        TaskPath            = "\Microsoft\Windows\Location"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "ProactiveScan"
        {
        TaskName            = "ProactiveScan"
        TaskPath            = "\Microsoft\Windows\CHKDSK"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "ProcessMemoryDiagnosticEvents"
        {
        TaskName            = "ProcessMemoryDiagnosticEvents"
        TaskPath            = "\Microsoft\Windows\MemoryDiagnostic"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }
        ScheduledTask "ProgramDataUpdater"
        {
        TaskName            = "ProgramDataUpdater"
        TaskPath            = "\Microsoft\Windows\Application Experience"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Proxy"
        {
        TaskName            = "Proxy"
        TaskPath            = "\Microsoft\Windows\Autochk"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "QueueReporting"
        {
        TaskName            = "QueueReporting"
        TaskPath            = "\Microsoft\Windows\Windows Error Reporting"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "RegIdleBackup"
        {
        TaskName            = "RegIdleBackup"
        TaskPath            = "\Microsoft\Windows\Registry"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "ResolutionHost"
        {
        TaskName            = "ResolutionHost"
        TaskPath            = "\Microsoft\Windows\WDI"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "RunFullMemoryDiagnostic"
        {
        TaskName            = "RunFullMemoryDiagnostic"
        TaskPath            = "\Microsoft\Windows\MemoryDiagnostic"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Scheduled"
        {
        TaskName            = "Scheduled"
        TaskPath            = "\Microsoft\Windows\Diagnosis"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "ScheduledDefrag"
        {
        TaskName            = "ScheduledDefrag"
        TaskPath            = "\Microsoft\Windows\Defrag"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "ServerManager"
        {
        TaskName            = "ServerManager"
        TaskPath            = "\Microsoft\Windows\Server Manager"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "StartComponentCleanup"
        {
        TaskName            = "StartComponentCleanup"
        TaskPath            = "\Microsoft\Windows\Servicing"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "StartupAppTask"
        {
        TaskName            = "StartupAppTask"
        TaskPath            = "\Microsoft\Windows\Application Experience"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "TPM-Maintenance"
        {
        TaskName            = "TPM-Maintenance"
        TaskPath            = "\Microsoft\Windows\TPM"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "UninstallDeviceTask"
        {
        TaskName            = "UninstallDeviceTask"
        TaskPath            = "\Microsoft\Windows\Bluetooth"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "UPnPHostConfig"
        {
        TaskName            = "UPnPHostConfig"
        TaskPath            = "\Microsoft\Windows\UPnP"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "UsbCeip"
        {
        TaskName            = "UsbCeip"
        TaskPath            = "\Microsoft\Windows\Customer Experience Improvement Program"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "VerifyWinRE"
        {
        TaskName            = "VerifyWinRE"
        TaskPath            = "\Microsoft\Windows\RecoveryEnvironment"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Windows Defender Cache Maintenance"
        {
        TaskName            = "Windows Defender Cache Maintenance"
        TaskPath            = "\Microsoft\Windows\Windows Defender"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Windows Defender Cleanup"
        {
        TaskName            = "Windows Defender Cleanup"
        TaskPath            = "\Microsoft\Windows\Windows Defender"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Windows Defender Scheduled Scan"
        {
        TaskName            = "Windows Defender Scheduled Scan"
        TaskPath            = "\Microsoft\Windows\Windows Defender"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Windows Defender Verification"
        {
        TaskName            = "Windows Defender Verification"
        TaskPath            = "\Microsoft\Windows\Windows Defender"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "UpdateLibrary"
        {
        TaskName            = "UpdateLibrary"
        TaskPath            = "\Microsoft\Windows\Windows Media Sharing"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "WinSAT"
        {
        TaskName            = "WinSAT"
        TaskPath            = "\Microsoft\Windows\Maintenance"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "Recovery-Check"
        {
        TaskName            = "Recovery-Check"
        TaskPath            = "\Microsoft\Windows\Workplace Join"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "ServerManager"
        {
        TaskName            = "ServerManager"
        TaskPath            = "\Microsoft\Windows\Server Manager"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        Registry "DeleteUserAppContainersOnLogoff"
        {
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        Ensure      = "Present"
        ValueName   = "DeleteUserAppContainersOnLogoff"
        ValueType   = "Dword"
        ValueData   = "1"
        }

        Registry "EnableAutoLayout"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout"
        Ensure      = "Present"
        ValueName   = "EnableAutoLayout"
        ValueType   = "DWORD"
        ValueData   = "0"
        }

        Registry "Enable"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction"
        Ensure      = "Present"
        ValueName   = "Enable"
        ValueType   = "String"
        ValueData   = "N"
        }

        Registry "ScreenSaveActive"
        {
        Key         = "HKEY_USERS\.DEFAULT\Control Panel\Desktop"
        Ensure      = "Present"
        ValueName   = "ScreenSaveActive"
        ValueType   = "DWORD"
        ValueData   = "0"
        }

        Registry "CrashDumpEnabled"
        {
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl"
        Ensure      = "Present"
        ValueName   = "CrashDumpEnabled"
        ValueType   = "DWORD"
        ValueData   = "0"
        }

        Registry "NtfsDisableLastAccessUpdate"
        {
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem"
        Ensure      = "Present"
        ValueName   = "NtfsDisableLastAccessUpdate"
        ValueType   = "DWORD"
        ValueData   = "1"
        }

        Registry "ErrorMode"
        {
        Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows"
        Ensure      = "Present"
        ValueName   = "ErrorMode"
        ValueType   = "DWORD"
        ValueData   = "2"
        }

        Registry "TimeOutValue"
        {
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk"
        Ensure      = "Present"
        ValueName   = "TimeOutValue"
        ValueType   = "DWORD"
        ValueData   = "0x000000C8"
        }

        Registry "NoAutoUpdate"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        Ensure      = "Present"
        ValueName   = "NoAutoUpdate"
        ValueType   = "DWORD"
        ValueData   = "1"
        }
    }
}
