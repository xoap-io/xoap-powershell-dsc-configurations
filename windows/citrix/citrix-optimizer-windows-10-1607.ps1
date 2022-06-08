Configuration 'citrix-optimizer-windows-10-1607'
{
Import-DSCResource -ModuleName "PSDesiredStateConfiguration"
Import-DSCResource -ModuleName "AuditPolicyDSC"
Import-DSCResource -ModuleName "SecurityPolicyDSC"
Import-DSCResource -ModuleName "DSCR_AppxPackage"
Import-DSCResource -ModuleName "ComputerManagementDsc"

    Node 'citrix-optimizer-windows-10-1607'
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

        Service "BthHFSrv"
        {
        Name        = "BthHFSrv"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "bthserv"
        {
        Name        = "bthserv"
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

        Service "DoSvc"
        {
        Name        = "DoSvc"
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

        Service "TrkWks"
        {
        Name        = "TrkWks"
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

        Service "RetailDemo"
        {
        Name        = "RetailDemo"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "wscsvc"
        {
        Name        = "wscsvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SensrSvc"
        {
        Name        = "SensrSvc"
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

        Service "wcncsvc"
        {
        Name        = "wcncsvc"
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

        Service "XblAuthManager"
        {
        Name        = "XblAuthManager"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "XblGameSave"
        {
        Name        = "XblGameSave"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "XboxNetApiSvc"
        {
        Name        = "XboxNetApiSvc"
        State       = "stopped"
        StartupType = "Disabled"
        }

        Service "SysMain"
        {
        Name        = "SysMain"
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

        cAppxProvisionedPackage "Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.DesktopAppInstaller_2021.1207.634.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.DesktopAppInstaller_2021.1207.634.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.Getstarted_2021.2111.2.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.Getstarted_2021.2111.2.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.MicrosoftOfficeHub_18.2110.13110.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.MicrosoftOfficeHub_18.2110.13110.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.MicrosoftSolitaireCollection_4.12.1050.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.MicrosoftSolitaireCollection_4.12.1050.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.MicrosoftStickyNotes_4.2.2.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.MicrosoftStickyNotes_4.2.2.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.Office.OneNote_16001.14326.20674.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.Office.OneNote_16001.14326.20674.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c"
        {
        PackageName = "Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.StorePurchaseApp_12109.1001.10.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.StorePurchaseApp_12109.1001.10.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.Windows.Photos_2021.21090.10008.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.Windows.Photos_2021.21090.10008.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsCalculator_2020.2103.8.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsCalculator_2020.2103.8.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsCamera_2021.105.10.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsCamera_2021.105.10.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "microsoft.windowscommunicationsapps_16005.14326.20544.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "microsoft.windowscommunicationsapps_16005.14326.20544.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsFeedbackHub_2022.106.2230.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsFeedbackHub_2022.106.2230.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.WindowsStore_22112.1401.2.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.WindowsStore_22112.1401.2.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.XboxIdentityProvider_12.83.12001.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.XboxIdentityProvider_12.83.12001.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
        }

        cAppxProvisionedPackage "Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe"
        {
        PackageName = "Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe"
        Ensure = "Absent"
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

        ScheduledTask "FamilySafetyMonitor"
        {
        TaskName            = "FamilySafetyMonitor"
        TaskPath            = "\Microsoft\Windows\Shell"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "FamilySafetyRefreshTask"
        {
        TaskName            = "FamilySafetyRefreshTask"
        TaskPath            = "\Microsoft\Windows\Shell"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "File History (maintenance mode)"
        {
        TaskName            = "File History (maintenance mode)"
        TaskPath            = "\Microsoft\Windows\FileHistory"
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

        ScheduledTask "SR"
        {
        TaskName            = "SR"
        TaskPath            = "\Microsoft\Windows\SystemRestore"
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

        ScheduledTask "WinSAT"
        {
        TaskName            = "WinSAT"
        TaskPath            = "\Microsoft\Windows\Maintenance"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "XblGameSaveTask"
        {
        TaskName            = "XblGameSaveTask"
        TaskPath            = "\Microsoft\XblGameSave"
        Enable              = [bool]$false
        Ensure              = "Absent"
        }

        ScheduledTask "XblGameSaveTaskLogon"
        {
        TaskName            = "XblGameSaveTaskLogon"
        TaskPath            = "\Microsoft\XblGameSave"
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

        Registry "HibernateEnabled"
        {
        Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power"
        Ensure      = "Present"
        ValueName   = "HibernateEnabled"
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

        Registry "AllowStorageSenseGlobal"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense"
        Ensure      = "Present"
        ValueName   = "AllowStorageSenseGlobal"
        ValueType   = "DWORD"
        ValueData   = "0"
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

        Registry "AllowCortana"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Ensure      = "Present"
        ValueName   = "AllowCortana"
        ValueType   = "DWORD"
        ValueData   = "0"
        }

        Registry "NoAutoUpdate"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        Ensure      = "Present"
        ValueName   = "NoAutoUpdate"
        ValueType   = "DWORD"
        ValueData   = "1"
        }

        Registry "CEIPEnable"
        {
        Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient\Windows"
        Ensure      = "Present"
        ValueName   = "CEIPEnable"
        ValueType   = "DWORD"
        ValueData   = "0"
        }
    }
}
