Configuration xoap-w10-1909-baseline-vdi
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DSCResource -ModuleName AuditPolicyDSC
    Import-DSCResource -ModuleName PowerShellAccessControl
    Import-DSCResource -ModuleName WindowsDefender
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName xPrinterManagement
    Import-DscResource -ModuleName OneDriveDsc
    Import-DscResource -ModuleName PendingReboot
    Import-DscResource -ModuleName XOAPBaselineModuleDSC
    Import-DSCResource -ModuleName XOAPVdiOptimizeW10Ent1909EnDSC
    Import-DscResource -ModuleName XOAPLCMDefaultsDSC

    Node xoap-w10-1909-baseline-vdi
    {
        cNtfsPermissionEntry PermissionSet1
        {
            Ensure = 'Present'
            Path = "C:\Windows\Temp"
            Principal = "S-1-1-0"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'ReadAndExecute'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
        }

        Registry "89B4C1CD-B018-4511-B0A1-5476DBF70820"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"
            Ensure = "Absent"
        }

        Registry "89B4C1CD-B018-4511-B0A1-5476DBF70820 x64"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"
            Ensure = "Absent"
        }

        Registry "89820200-ECBD-11cf-8B85-00AA005B4383"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89820200-ECBD-11cf-8B85-00AA005B4383}"
            Ensure = "Absent"
        }

        Registry "44BBA840-CC51-11CF-AAFA-00AA00B6015C"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{44BBA840-CC51-11CF-AAFA-00AA00B6015C}"
            Ensure = "Absent"
        }

        Registry "2C7339CF-2B09-4501-B3F3-F3508C9228ED"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{2C7339CF-2B09-4501-B3F3-F3508C9228ED}"
            Ensure = "Absent"
        }

        Registry "89820200-ECBD-11cf-8B85-00AA005B4340"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89820200-ECBD-11cf-8B85-00AA005B4340}"
            Ensure = "Absent"
        }

        Registry "6BF52A52-394A-11d3-B153-00C04F79FAA6"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{6BF52A52-394A-11d3-B153-00C04F79FAA6}"
            Ensure = "Absent"
        }

        Registry "22d6f312-b0f6-11d0-94ab-0080c74c7e95"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}"
            Ensure = "Absent"
        }

        Registry "22d6f312-b0f6-11d0-94ab-0080c74c7e95 x64"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}"
            Ensure = "Absent"
        }

        Registry "A509B1A8-37EF-4b3f-8CFC-4F3A74704073"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure = "Absent"
        }

        Registry "A509B1A8-37EF-4b3f-8CFC-4F3A74704073 x64"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure = "Absent"
        }

        Registry "2D46B6DC-2207-486B-B523-A557E6D54B47"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{2D46B6DC-2207-486B-B523-A557E6D54B47}"
            Ensure = "Absent"
        }

         Registry DisableIEFirstRun
         {
             Key               = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InternetExplorer\Main"
             Ensure            = "Present"
             ValueName         = "DisableFirstRunCustomize"
             ValueType         = "Dword"
             ValueData        = "00000001"
         }

         Registry IETempPath
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths"
             Ensure          = "Present"
             ValueName       = "Paths"
             ValueType       = "Dword"
             ValueData       = "000000004"
         }

         Registry IETempPath1
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path1"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         Registry "IETempPath2"
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path2"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         Registry "IETempPath3"
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path3"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         Registry "IETempPath4"
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path4"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         Registry DisableCEIP
         {
             Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\SQMClient\Windows\"
             Ensure      = "Present"
             ValueName   = "CEIPEnable"
             ValueType   = "dword"
             ValueData   = "0"
         }

         Registry DisableWindowsDefender
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
             Ensure      = "Present"
             ValueName   = "Real-Time Protection"
             ValueType   = "dword"
             ValueData   = "1"
         }

         Registry DisableAntiSpyWare
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware"
             Ensure      = "Present"
             ValueName   = "DisableAntiSpyware"
             ValueType   = "dword"
             ValueData   = "1"
         }

         Registry DisableLocation
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
             Ensure      = "Present"
             ValueName   = "AllowSearchToUseLocation"
             ValueType   = "dword"
             ValueData   = "00000000"
         }

         Registry DisableSearchWeb
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
             Ensure      = "Present"
             ValueName   = "ConnectedSearchUseWeb"
             ValueType   = "dword"
             ValueData   = "00000000"
         }

         Registry DisableAdditionalInfoErrorReports
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
             Ensure      = "Present"
             ValueName   = "DontSendAdditionalData"
             ValueType   = "dword"
             ValueData   = "00000001"
         }

         Registry InactivityTimeoutSecs
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
             Ensure      = "Present"
             ValueName   = "InactivityTimeoutSecs"
             ValueType   = "dword"
             ValueData   = "00000600"
         }

         Registry DisableNetworkLocation
         {
             Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Network"
             Ensure      = "Present"
             ValueName   = "NewNetworkWindowOff"
             ValueType   = "dword"
             ValueData   = "1"
         }

         Registry DisableTCPTaskOffload
         {
             Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters\"
             Ensure      = "Present"
             ValueName   = "DisableTaskOffload"
             ValueType   = "dword"
             ValueData   = "1"
         }

         ScheduledTask "SmartScreenSpecific"
         {
             TaskName = "SmartScreenSpecific"
             TaskPath = "\Microsoft\Windows\AppID\"
             Ensure = 'Absent'
         }

         ScheduledTask "MicrosoftCompatibilityAppraiser"
         {
             TaskName = "Microsoft Compatibility Appraiser"
             TaskPath = "\Microsoft\Windows\Application Experience\"
             Ensure = 'Absent'
         }

         ScheduledTask "ProgramDataUpdater"
         {
             TaskName = "ProgramDataUpdater"
             TaskPath = "\Microsoft\Windows\Application Experience\"
             Ensure = 'Absent'
         }

         ScheduledTask "StartupAppTask"
         {
             TaskName = "StartupAppTask"
             TaskPath = "\Microsoft\Windows\Application Experience\"
             Ensure = 'Absent'
         }

         ScheduledTask Proxy
         {
             TaskName = "Proxy"
             TaskPath = "\Microsoft\Windows\Autochk\"
             Ensure = 'Absent'
         }

         ScheduledTask "UninstallDeviceTask"
         {
             TaskName = "UninstallDeviceTask"
             TaskPath = "\Microsoft\Windows\Bluetooth\"
             Ensure = 'Absent'
         }

         ScheduledTask "ProactiveScan"
         {
             TaskName = "ProactiveScan"
             TaskPath = "\Microsoft\Windows\Chkdsk\"
             Ensure = 'Absent'
         }

         ScheduledTask "CreateObjectTask"
         {
             TaskName = "CreateObjectTask"
             TaskPath = "\Microsoft\Windows\CloudExperienceHost\"
             Ensure = 'Absent'
         }

         ScheduledTask "Consolidator"
         {
             TaskName = "Consolidator"
             TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
             Ensure = 'Absent'
         }

         ScheduledTask "KernelCeipTask"
         {
             TaskName = "KernelCeipTask"
             TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
             Ensure = 'Absent'
         }

         ScheduledTask "UsbCeip"
         {
             TaskName = "UsbCeip"
             TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
             Ensure = 'Absent'
         }

         ScheduledTask "ScheduledDefrag"
         {
             TaskName = "ScheduledDefrag"
             TaskPath = "\Microsoft\Windows\Defrag\"
             Ensure = 'Absent'
         }

         ScheduledTask "Scheduled"
         {
             TaskName = "Scheduled"
             TaskPath = "\Microsoft\Windows\Diagnosis\"
             Ensure = 'Absent'
         }

         ScheduledTask "Microsoft-Windows-DiskDiagnosticDataCollector"
         {
             TaskName = "Microsoft-Windows-DiskDiagnosticDataCollector"
             TaskPath = "\Microsoft\Windows\DiskDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "Microsoft-Windows-DiskDiagnosticResolver"
         {
             TaskName = "Microsoft-Windows-DiskDiagnosticResolver"
             TaskPath = "\Microsoft\Windows\DiskDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "DmClient"
         {
             TaskName = "DmClient"
             TaskPath = "\Microsoft\Windows\Feedback\Siuf\"
             Ensure = 'Absent'
         }

         ScheduledTask "WinSAT"
         {
             TaskName = "WinSAT"
             TaskPath = "\Microsoft\Windows\Maintenance\"
             Ensure = 'Absent'
         }

         ScheduledTask "MapsToastTask"
         {
             TaskName = "MapsToastTask"
             TaskPath = "\Microsoft\Windows\Maps\"
             Ensure = 'Absent'
         }

         ScheduledTask "MapsUpdateTask"
         {
             TaskName = "MapsUpdateTask"
             TaskPath = "\Microsoft\Windows\Maps\"
             Ensure = 'Absent'
         }

         ScheduledTask "ProcessMemoryDiagnosticEvents"
         {
             TaskName = "ProcessMemoryDiagnosticEvents"
             TaskPath = "\Microsoft\Windows\MemoryDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "RunFullMemoryDiagnostic"
         {
             TaskName = "RunFullMemoryDiagnostic"
             TaskPath = "\Microsoft\Windows\MemoryDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "MNOMetadataParse"
         {
             TaskName = "MNO Metadata Parser"
             TaskPath = "\Microsoft\Windows\Mobile Broadband Accounts\"
             Ensure = 'Absent'
         }

         ScheduledTask "AnalyzeSystem"
         {
             TaskName = "AnalyzeSystem"
             TaskPath = "\Microsoft\Windows\Power Efficiency Diagnostics\"
             Ensure = 'Absent'
         }

         ScheduledTask "MobilityManager"
         {
             TaskName = "MobilityManager"
             TaskPath = "\Microsoft\Windows\Ras\"
             Ensure = 'Absent'
         }

         ScheduledTask "RegIdleBackup"
         {
             TaskName = "RegIdleBackup"
             TaskPath = "\Microsoft\Windows\Registry\"
             Ensure = 'Absent'
         }

         ScheduledTask "FamilySafetyMonitor"
         {
             TaskName = "FamilySafetyMonitor"
             TaskPath = "\Microsoft\Windows\Shell\"
             Ensure = 'Absent'
         }

         ScheduledTask "FamilySafetyRefresh"
         {
             TaskName = "FamilySafetyRefreshTask"
             TaskPath = "\Microsoft\Windows\Shell\"
             Ensure = 'Absent'
         }

         ScheduledTask "SR"
         {
             TaskName = "SR"
             TaskPath = "\Microsoft\Windows\SystemRestore\"
             Ensure = 'Absent'
         }

         ScheduledTask "Tpm-Maintenance"
         {
             TaskName = "Tpm-Maintenance"
             TaskPath = "\Microsoft\Windows\TPM\"
             Ensure = 'Absent'
         }

         ScheduledTask "UPnPHostConfig"
         {
             TaskName = "UPnPHostConfig"
             TaskPath = "\Microsoft\Windows\UPnP\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderCacheMaintenance"
         {
             TaskName = "Windows Defender Cache Maintenance"
             TaskPath = "\Microsoft\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderCleanup"
         {
             TaskName = "Windows Defender Cleanup"
             TaskPath = "\Microsoft\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderScheduledScan"
         {
             TaskName = "Windows Defender Scheduled Scan"
             TaskPath = "\Microsoft\Windows\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderVerification"
         {
             TaskName = "Windows Defender Verification"
             TaskPath = "\Microsoft\Windows\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "QueueReporting"
         {
             TaskName = "QueueReporting"
             TaskPath = "\Microsoft\Windows\Windows Error Reporting\"
             Ensure = 'Absent'
         }

         ScheduledTask "BfeonServiceStartTypeChange"
         {
             TaskName = "BfeonServiceStartTypeChange"
             TaskPath = "\Microsoft\Windows\Windows Filtering Platform\"
             Ensure = 'Absent'
         }

         ScheduledTask "UpdateLibrary"
         {
             TaskName = "UpdateLibrary"
             TaskPath = "\Microsoft\Windows\Windows Media Sharing\"
             Ensure = 'Absent'
         }

         ScheduledTask "WIM-Hash-Management"
         {
             TaskName = "WIM-Hash-Management"
             TaskPath = "\Microsoft\Windows\WOF\"
             Ensure = 'Absent'
         }

         ScheduledTask "WIM-Hash-Validation"
         {
             TaskName = "WIM-Hash-Validation"
             TaskPath = "\Microsoft\Windows\WOF\"
             Ensure = 'Absent'
         }

         ScheduledTask "XblGameSaveTask"
         {
             TaskName = "XblGameSaveTask"
             TaskPath = "\Microsoft\XblGameSave\"
             Ensure = 'Absent'
         }

         ScheduledTask "XblGameSaveTaskLogon"
         {
             TaskName = "XblGameSaveTaskLogon"
             TaskPath = "\Microsoft\XblGameSave\"
             Ensure = 'Absent'
         }

        Registry IncreaseServicesStartupTimeout
        {
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control"
            Ensure      = "Present"
            ValueName   = "ServicesPipeTimeout"
            ValueType   = "Dword"
            ValueData   = "120000"
        }

        Service AJRouter
        {
            Name        = "AJRouter"
            State       = "stopped"
            StartupType = "Disabled"
        }

        Service ALG
        {
            Name        = "ALG"
            State       = "stopped"
            StartupType = "Disabled"
        }

        Service "BITS"
        {
            Name        = "BITS"
            State       = "stopped"
            StartupType = "Manual"
        }

        Service "PeerDistSvc"
        {
            Name        = "PeerDistSvc"
            State       = "stopped"
            StartupType = "Disabled"
        }

        Service "WdiServiceHost"
        {
        Name        = "WdiServiceHost"
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

        Service "RetailDemo"
        {
            Name        = "RetailDemo"
            State       = "stopped"
            StartupType = "Disabled"
        }

        Service "SensrSvc"
        {
            Name        = "SensrSvc"
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

        Registry DisableFirstLogonAnimation
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Ensure      = "Present"
            ValueName   = "EnableFirstLogonAnimation"
            ValueType   = "Dword"
            ValueData   = "00000000"
        }

        Registry DisableHardErrorMessages
        {
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows"
            Ensure      = "Present"
            ValueName   = "ErrorMode"
            ValueType   = "Dword"
            ValueData   = "00000002"
        }

        Registry DisableDump
        {
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\CrashControl"
            Ensure      = "Present"
            ValueName   = "CrashDumpEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry DefragBootOptimizeFunction
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout"
            Ensure      = "Present"
            ValueName   = "EnableAutoLayout"
            ValueType   = "Dword"
            ValueData   = "00000000"
        }

        Registry IncreaseDiskIOTimeout
        {
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk"
            Ensure      = "Present"
            ValueName   = "TimeOutValue"
            ValueType   = "Dword"
            ValueData   = "200"
        }

        Registry MemoryManagement
        {
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management"
            Ensure      = "Present"
            ValueName   = "DisablePagingExecutive"
            ValueType   = "Dword"
            ValueData   = "00000001"
        }

        Registry RecommendedMetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\Recommended"
            Ensure      = "Present"
            ValueName   = "MetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry MetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\"
            Ensure      = "Present"
            ValueName   = "MetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry RecommendedDeviceMetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\Recommended"
            Ensure      = "Present"
            ValueName   = "DeviceMetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry DeviceMetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\"
            Ensure      = "Present"
            ValueName   = "DeviceMetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry DisableWindowsConsumerFeatures
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "DisableWindowsConsumerFeatures"
            ValueType   = "dword"
            ValueData   = "00000001"
        }

        Registry ContentDeliveryAllowed
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "ContentDeliveryAllowed"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry OemPreInstalledAppsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "OemPreInstalledAppsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry PreInstalledAppsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "PreInstalledAppsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry PreInstalledAppsEverEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "PreInstalledAppsEverEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry SilentInstalledAppsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "SilentInstalledAppsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }
        Registry SystemPaneSuggestionsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "SystemPaneSuggestionsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry DisableTelemetryCollection
        {
            ValueName   = "AllowTelemetry"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry DisableSensors
        {
            ValueName   = "DisableSensors"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry DoNotTrack
        {
            ValueName   = "DoNotTrack"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\Main"
            ValueType   = "dword"
            ValueData   = "1"
        }

        {
            ValueName   = "PreventLiveTileDataCollection"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\Main"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry EnableExtendedBooksTelemetry
        {
            ValueName   = "EnableExtendedBooksTelemetry"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry MicrosoftEdgeDataOptIn
        {
            ValueName   = "MicrosoftEdgeDataOptIn"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry MapsAutoUpdate
        {
            ValueName   = "AutoUpdateEnabled"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\System\Maps"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry AutoLoggerDiagtrackListener
        {
            ValueName   = "Start"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable Authenticated Proxy usage
        Registry 'DisableEnterpriseAuthProxy'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DisableEnterpriseAuthProxy'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'FirefoxDisableTelemetry'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'BlockAboutConfig'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'BlockAboutConfig'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'BlockAboutProfiles'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'BlockAboutProfiles'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'DontCheckDefaultBrowser'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'DontCheckDefaultBrowser'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry OfficeSharedComputerLicensing
        {
            ValueName   = "SharedComputerLicensing"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
            ValueType   = "String"
            ValueData   = "0"
        }

        Registry FeedbackEnabled
        {
            ValueName   = "Enabled"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry includescreenshot
        {
            ValueName   = "includescreenshot"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry notrack
        {
            ValueName   = "notrack"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\general"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry optindisable
        {
            ValueName   = "optindisable"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\general"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry shownfirstrunoptin
        {
            ValueName   = "shownfirstrunoptin"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\general"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry ptwoptin
        {
            ValueName   = "ptwoptin"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry bootedrtm
        {
            ValueName   = "bootedrtm"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\firstrun"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry disablemovie
        {
            ValueName   = "disablemovie"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\firstrun"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry enablefileobfuscation
        {
            ValueName   = "enablefileobfuscation"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry enablelogging
        {
            ValueName   = "enablelogging"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry accesssolution
        {
            ValueName   = "accesssolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }


        Registry olksolution
        {
            ValueName   = "olksolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry onenotesolution
        {
            ValueName   = "onenotesolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry pptsolution
        {
            ValueName   = "pptsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry Projectsolution
        {
            ValueName   = "projectsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry publishersolution
        {
            ValueName   = "publishersolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry visiosolution
        {
            ValueName   = "visiosolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry wdsolution
        {
            ValueName   = "wdsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry xlsolution
        {
            ValueName   = "xlsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry agave
        {
            ValueName   = "agave"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry appaddins
        {
            ValueName   = "appaddins"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry comaddins
        {
            ValueName   = "comaddins"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry documentfiles
        {
            ValueName   = "documentfiles"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry templatefiles
        {
            ValueName   = "templatefiles"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry onlinerepair
        {
            ValueName   = "onlinerepair"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry fallbacktocdn
        {
            ValueName   = "fallbacktocdn"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry OutlookEnableLogging
        {
            ValueName   = "EnableLogging"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Options\Mail"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable Word logging
        Registry WordEnableLogging
        {
            ValueName   = "EnableLogging"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry DisableClientTelemetry
        {
            ValueName   = "DisableTelemetry"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Office\Common\ClientTelemetry"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry disableboottoofficestart
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry qmenable
        {
            ValueName   = "qmenable"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry sendcustomerdata
        {
            ValueName   = "sendcustomerdata"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry updatereliabilitydata
        {
            ValueName   = "updatereliabilitydata"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry disableboottoofficestartGeneral
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\General"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry ShownFileFmtPrompt
        {
            ValueName   = "ShownFileFmtPrompt"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\General"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry disableboottoofficestartInternet
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Internet"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry serviceleveloptions
        {
            ValueName   = "serviceleveloptions"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Internet"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry disableboottoofficestartPTWatson
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\PTWatson"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry disablereporting
        {
            ValueName   = "disablereporting"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Security\FileValidation"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry disableautomaticsendtracing
        {
            ValueName   = "disableautomaticsendtracing"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Lync"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Script "powercfg"{
            TestScript = {
                $x =  Get-WmiObject -Class Win32_Powerplan -Namespace root\CIMV2\Power
                $y = $x.InstanceID
                [bool]$t = $true
                foreach($s in $y){
                $a1 = powercfg -Query $($s.Split("{}")[1]) SUB_SLEEP STANDBYIDLE
                $b1 = $a1 | Select-Object -Last 3
                $c1 = $b1 | Select-Object -First 2
                $z1_1 = $c1.Split(":")[1] -eq " 0x00000000"
                $z1_2 = $c1.Split(":")[3] -eq " 0x00000000"

                $a2 = powercfg -Query $($s.Split("{}")[1]) SUB_VIDEO VIDEOIDLE
                $b2 = $a2 | Select-Object -Last 3
                $c2 = $b2 | Select-Object -First 2
                $z2_1 = $c2.Split(":")[1] -eq " 0x00000708"
                $z2_2 = $c2.Split(":")[3] -eq " 0x00000708"

                $a3 = powercfg -Query $($s.Split("{}")[1]) SUB_DISK DISKIDLE
                $b3 = $a3 | Select-Object -Last 3
                $c3 = $b3 | Select-Object -First 2
                $z3_1 = $c3.Split(":")[1] -eq " 0x00000000"
                $z3_2 = $c3.Split(":")[3] -eq " 0x00000000"

                $a4 = powercfg -Query $($s.Split("{}")[1]) SUB_SLEEP HIBERNATEIDLE
                $b4 = $a4 | Select-Object -Last 3
                $c4 = $b4 | Select-Object -First 2
                $z4_1 = $c4.Split(":")[1] -eq " 0x00000000"
                $z4_2 = $c4.Split(":")[3] -eq " 0x00000000"

                $t = $z1_1 -and $z1_2 -and $z2_1 -and $z2_2 -and $z3_1 -and $z3_2 -and $z4_1 -and $z4_2  -and $t
                            }
                $t
                    }
            SetScript = {
                $activescheme = powercfg /getactivescheme
                $schemestemp = powercfg -l
                $schemes = $schemestemp | select-object -skip 3

                foreach($s in $schemes){
                    Write-Output "Power Configuration $($s.Split( )[5,6]) will be set to Never sleep."
                    powercfg /setactive $s.Split( )[3]
                    powercfg /change monitor-timeout-ac 30
                    powercfg /change monitor-timeout-dc 30
                    powercfg /change disk-timeout-ac 0
                    powercfg /change disk-timeout-dc 0
                    powercfg /change standby-timeout-ac 0
                    powercfg /change standby-timeout-dc 0
                    powercfg /change hibernate-timeout-ac 0
                    powercfg /change hibernate-timeout-dc 0
                         }
                powercfg /setactive $activescheme.Split( )[3]
                    }
            GetScript = {
                    }
        }

        Script "InstallPowershellModules
{
            TestScript = {
            $t1 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\AzureRM"
            $t2 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\AzureAD"
            $t3 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\Microsoft.Online.SharePoint.PowerShell"
            $t4 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\PendingReboot"
            $t5 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\BurntToast"

            [bool]$t = $true
            $t= $t1 -and $t2 -and $t3 -and $t4 -and $t5
            $t
            }

            SetScript = {
            Install-Module -Name AzureAD -AllowClobber
            Install-Module -Name AzureRM -AllowClobber
            Install-Module -Name Microsoft.Online.SharePoint.PowerShell -AllowClobber
            Install-Module -Name PendingReboot -AllowClobber
            Install-Module -Name BurntToast -AllowClobber
                    }

            GetScript = {
                    }
        }

        SecurityOption AccountSecurityOptions {
            Name = 'AccountSecurityOptions'
        Accounts_Guest_account_status = 'Disabled'
             }

        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }

        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = 'Guests'
        }

        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'Guests'
        }

        OneDrive RISCAccountConfig {

            FilesOnDemandEnabled = 'Present'
            SilentAccountConfig = 'Present'

        }

        XOAPVdiOptimizeMeta "XOAPVdiOptimizeW10Ent1909EnDSC Config"
        {
            Include_XOAPVdiOptimizeWindowsMediaPlayerRemoval = $true
            Include_XOAPVdiOptimizeAppxPackagesRemoval = $true
            Include_XOAPVdiOptimizeDisableScheduleTasks = $true
            Include_XOAPVdiOptimizeUninstallOneDrive = $true
            Include_XOAPVdiOptimizeServicesAutologgersDisable = $true
            Include_XOAPVdiOptimizeServicesDisable = $true
            Include_XOAPVdiOptimizeNetworkOptimization = $true
        }

        XOAPLCMDefaultsMeta "Disable RebootIfNeeded"
        {
            Disable_Reboot = $true
        }
     }
}
xoap-w10-1909-baseline-vdi
