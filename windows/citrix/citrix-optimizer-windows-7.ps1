Configuration 'citrix-optimizer-windows-7'
{
Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
Import-DSCResource -ModuleName "ComputerManagementDsc"

    Node 'citrix-optimizer-windows-7'
    {
        Service "SensrSvc"
        {
        Name        = "SensrSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "ALG"
        {
        Name        = "ALG"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "BITS"
        {
        Name        = "BITS"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "BDESVC"
        {
        Name        = "BDESVC"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "wbengine"
        {
        Name        = "wbengine"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "PeerDistSvc"
        {
        Name        = "PeerDistSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "Browser"
        {
        Name        = "Browser"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "UxSms"
        {
        Name        = "UxSms"
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

        Service "EFS"
        {
        Name        = "EFS"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "Fax"
        {
        Name        = "Fax"
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

        Service "HomeGroupListener"
        {
        Name        = "HomeGroupListener"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "HomeGroupProvider"
        {
        Name        = "HomeGroupProvider"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "UI0Detect"
        {
        Name        = "UI0Detect"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SharedAccess"
        {
        Name        = "SharedAccess"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "iphlpsvc"
        {
        Name        = "iphlpsvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "Mcx2Svc"
        {
        Name        = "Mcx2Svc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "MSiSCSI"
        {
        Name        = "MSiSCSI"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "CscService"
        {
        Name        = "CscService"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "wercplsupport"
        {
        Name        = "wercplsupport"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SstpSvc"
        {
        Name        = "SstpSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "wscsvc"
        {
        Name        = "wscsvc"
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

        Service "SDRSVC"
        {
        Name        = "SDRSVC"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "wcncsvc"
        {
        Name        = "wcncsvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WinDefend"
        {
        Name        = "WinDefend"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "ehRecvr"
        {
        Name        = "ehRecvr"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "ehSched"
        {
        Name        = "ehSched"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WMPNetworkSvc"
        {
        Name        = "WMPNetworkSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WlanSvc"
        {
        Name        = "WlanSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "WwanSvc"
        {
        Name        = "WwanSvc"
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

        ScheduledTask "AitAgent"
        {
        TaskName            = "AitAgent"
        TaskPath            = "\Microsoft\Windows\Application Experience"
        Enable              = [bool]$false
        Ensure              = "Absent"
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

        ScheduledTask "KernelCeipTask"
        {
        TaskName            = "KernelCeipTask"
        TaskPath            = "\Microsoft\Windows\Customer Experience Improvement Program"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "CorruptionDetector"
        {
        TaskName            = "CorruptionDetector"
        TaskPath            = "\Microsoft\Windows\MemoryDiagnostic"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "DecompressionFailureDetector"
        {
        TaskName            = "DecompressionFailureDetector"
        TaskPath            = "\Microsoft\Windows\MemoryDiagnostic"
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

        ScheduledTask "MP Scheduled Scan"
        {
        TaskName            = "MP Scheduled Scan"
        TaskPath            = "\Microsoft\Windows Defender"
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

        ScheduledTask "SR"
        {
        TaskName            = "SR"
        TaskPath            = "\Microsoft\Windows\SystemRestore"
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

        ScheduledTask "ConfigNotification"
        {
        TaskName            = "ConfigNotification"
        TaskPath            = "\Microsoft\Windows\WindowsBackup"
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

        ScheduledTask "WinSAT"
        {
        TaskName            = "WinSAT"
        TaskPath            = "\Microsoft\Windows\Maintenance"
        Enable              = [bool]$false
        Ensure              = "Absent"
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

        Registry "EnableFirstLogonAnimation"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Ensure      = "Present"
        ValueName   = "EnableFirstLogonAnimation"
        ValueType   = "DWORD"
        ValueData   = "0"
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
