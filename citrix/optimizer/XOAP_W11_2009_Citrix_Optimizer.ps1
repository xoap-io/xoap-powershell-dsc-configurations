Configuration 'XOAP_W11_2009_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
    Import-DscResource -ModuleName 'XOAPAppxPackageDSC' -ModuleVersion '0.1.0'

    Node 'XOAP_W11_2009_Citrix_Optimizer'
    {
        Service 'AJRouter'
        {
            Name        = 'AJRouter'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'ALG'
        {
            Name        = 'ALG'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'BthAvctpSvc'
        {
            Name        = 'BthAvctpSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'BDESVC'
        {
            Name        = 'BDESVC'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'wbengine'
        {
            Name        = 'wbengine'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'BTAGService'
        {
            Name        = 'BTAGService'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'bthserv'
        {
            Name        = 'bthserv'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'PeerDistSvc'
        {
            Name        = 'PeerDistSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'DusmSvc'
        {
            Name        = 'DusmSvc'
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

        Service 'TrkWks'
        {
            Name        = 'TrkWks'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'MapsBroker'
        {
            Name        = 'MapsBroker'
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

        Service 'lfsvc'
        {
            Name        = 'lfsvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'SharedAccess'
        {
            Name        = 'SharedAccess'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'CscService'
        {
            Name        = 'CscService'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'WpcMonSvc'
        {
            Name        = 'WpcMonSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'RetailDemo'
        {
            Name        = 'RetailDemo'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'SensrSvc'
        {
            Name        = 'SensrSvc'
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

        Service 'VacSvc'
        {
            Name        = 'VacSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'wcncsvc'
        {
            Name        = 'wcncsvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'WMPNetworkSvc'
        {
            Name        = 'WMPNetworkSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'icssvc'
        {
            Name        = 'icssvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'WlanSvc'
        {
            Name        = 'WlanSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'WwanSvc'
        {
            Name        = 'WwanSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'XboxGipSvc'
        {
            Name        = 'XboxGipSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'XblAuthManager'
        {
            Name        = 'XblAuthManager'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'XblGameSave'
        {
            Name        = 'XblGameSave'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'XboxNetApiSvc'
        {
            Name        = 'XboxNetApiSvc'
            State       = 'stopped'
            StartupType = 'Disabled'
        }

        Service 'SysMain'
        {
            Name        = 'SysMain'
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

        Service 'defragsvc'
        {
            Name        = 'defragsvc'
            State       = 'stopped'
            StartupType = 'Manual'
        }

        cAppxProvisionedPackage 'Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.DesktopAppInstaller_2021.1207.634.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.DesktopAppInstaller_2021.1207.634.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.GetHelp_10.2111.43421.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.GetHelp_10.2111.43421.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.Getstarted_2021.2111.2.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.Getstarted_2021.2111.2.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.HEIFImageExtension_1.0.43012.0_x64__8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.HEIFImageExtension_1.0.43012.0_x64__8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.Microsoft3DViewer_2021.2107.7012.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.Microsoft3DViewer_2021.2107.7012.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.MicrosoftOfficeHub_18.2110.13110.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.MicrosoftOfficeHub_18.2110.13110.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.MicrosoftSolitaireCollection_4.12.1050.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.MicrosoftSolitaireCollection_4.12.1050.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.MicrosoftStickyNotes_4.2.2.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.MicrosoftStickyNotes_4.2.2.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.MixedReality.Portal_2000.21051.1282.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.MixedReality.Portal_2000.21051.1282.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.MSPaint_2021.2105.4017.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.MSPaint_2021.2105.4017.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.Office.OneNote_16001.14326.20674.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.Office.OneNote_16001.14326.20674.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.ScreenSketch_2020.814.2355.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.ScreenSketch_2020.814.2355.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c'
        {
            PackageName = 'Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.StorePurchaseApp_12109.1001.10.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.StorePurchaseApp_12109.1001.10.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.VP9VideoExtensions_1.0.42791.0_x64__8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.VP9VideoExtensions_1.0.42791.0_x64__8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.Wallet_2.4.18324.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.Wallet_2.4.18324.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WebMediaExtensions_1.0.42192.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WebMediaExtensions_1.0.42192.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WebpImageExtension_1.0.42351.0_x64__8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WebpImageExtension_1.0.42351.0_x64__8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.Windows.Photos_2021.21090.10008.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.Windows.Photos_2021.21090.10008.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsCalculator_2020.2103.8.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsCalculator_2020.2103.8.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsCamera_2021.105.10.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsCamera_2021.105.10.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'microsoft.windowscommunicationsapps_16005.14326.20544.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'microsoft.windowscommunicationsapps_16005.14326.20544.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsFeedbackHub_2022.106.2230.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsFeedbackHub_2022.106.2230.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.WindowsStore_22112.1401.2.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.WindowsStore_22112.1401.2.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.Xbox.TCUI_1.24.10001.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.Xbox.TCUI_1.24.10001.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.XboxGameOverlay_1.54.4001.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.XboxGameOverlay_1.54.4001.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.XboxGamingOverlay_5.721.12013.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.XboxGamingOverlay_5.721.12013.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.XboxIdentityProvider_12.83.12001.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.XboxIdentityProvider_12.83.12001.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.XboxSpeechToTextOverlay_1.21.13002.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.XboxSpeechToTextOverlay_1.21.13002.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.YourPhone_1.21121.250.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.YourPhone_1.21121.250.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        cAppxProvisionedPackage 'Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe'
        {
            PackageName = 'Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }

        ScheduledTask 'AnalyzeSystem'
        {
            TaskName            = 'AnalyzeSystem'
            TaskPath            = '\Microsoft\Windows\Power Efficiency Diagnostics'
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

        ScheduledTask 'Cellular'
        {
            TaskName            = 'Cellular'
            TaskPath            = '\Microsoft\Windows\Management\Provisioning\'
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

        ScheduledTask 'Diagnostics'
        {
            TaskName            = 'Diagnostics'
            TaskPath            = '\Microsoft\Windows\DiskFootprint\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'FamilySafetyMonitor'
        {
            TaskName            = 'FamilySafetyMonitor'
            TaskPath            = '\Microsoft\Windows\Shell'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'FamilySafetyRefreshTask'
        {
            TaskName            = 'FamilySafetyRefreshTask'
            TaskPath            = '\Microsoft\Windows\Shell'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'File History (maintenance mode)'
        {
            TaskName            = 'File History (maintenance mode)'
            TaskPath            = '\Microsoft\Windows\FileHistory'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'WindowsActionDialog'
        {
            TaskName            = 'WindowsActionDialog'
            TaskPath            = '\Microsoft\Windows\Location'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'Notifications'
        {
            TaskName            = 'Notifications'
            TaskPath            = '\Microsoft\Windows\Location'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'MapsToastTask'
        {
            TaskName            = 'MapsToastTask'
            TaskPath            = '\Microsoft\Windows\Maps'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'MapsUpdateTask'
        {
            TaskName            = 'MapsUpdateTask'
            TaskPath            = '\Microsoft\Windows\Maps'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'Microsoft Compatibility Appraiser'
        {
            TaskName            = 'Microsoft Compatibility Appraiser'
            TaskPath            = '\Microsoft\Windows\Application Experience'
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

        ScheduledTask 'MNO Metadata Parser'
        {
            TaskName            = 'MNO Metadata Parser'
            TaskPath            = '\Microsoft\Windows\Mobile Broadband Accounts'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'NotificationTask'
        {
            TaskName            = 'NotificationTask'
            TaskPath            = '\Microsoft\Windows\WwanSvc\'
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

        ScheduledTask 'ProcessMemoryDiagnosticEvents'
        {
            TaskName            = 'ProcessMemoryDiagnosticEvents'
            TaskPath            = '\Microsoft\Windows\MemoryDiagnostic'
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

        ScheduledTask 'RecommendedTroubleshootingScanner'
        {
            TaskName            = 'RecommendedTroubleshootingScanner'
            TaskPath            = '\Microsoft\Windows\Diagnosis\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'ReconcileFeatures'
        {
            TaskName            = 'ReconcileFeatures'
            TaskPath            = '\Microsoft\Windows\Flighting\FeatureConfig\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'ReconcileLanguageResources'
        {
            TaskName            = 'ReconcileLanguageResources'
            TaskPath            = '\Microsoft\Windows\LanguageComponentsInstaller\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'RefreshCache'
        {
            TaskName            = 'RefreshCache'
            TaskPath            = '\Microsoft\Windows\Flighting\OneSettings\'
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

        ScheduledTask 'ResPriStaticDbSync'
        {
            TaskName            = 'ResPriStaticDbSync'
            TaskPath            = '\Microsoft\Windows\Sysmain\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'RunFullMemoryDiagnostic'
        {
            TaskName            = 'RunFullMemoryDiagnostic'
            TaskPath            = '\Microsoft\Windows\MemoryDiagnostic'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'ScanForUpdates'
        {
            TaskName            = 'ScanForUpdates'
            TaskPath            = '\Microsoft\Windows\InstallService\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'ScanForUpdatesAsUser'
        {
            TaskName            = 'ScanForUpdatesAsUser'
            TaskPath            = '\Microsoft\Windows\InstallService\'
            Enable              = $false
            Ensure              = 'Absent'
        }


        ScheduledTask 'Scheduled'
        {
            TaskName            = 'Scheduled'
            TaskPath            = '\Microsoft\Windows\Diagnosis'
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

        ScheduledTask 'SilentCleanup'
        {
            TaskName            = 'SilentCleanup'
            TaskPath            = '\Microsoft\Windows\DiskCleanup\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'SmartRetry'
        {
            TaskName            = 'SmartRetry'
            TaskPath            = '\Microsoft\Windows\InstallService\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'SpaceAgentTask'
        {
            TaskName            = 'SpaceAgentTask'
            TaskPath            = '\Microsoft\Windows\SpacePort\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'SpaceManagerTask'
        {
            TaskName            = 'SpaceManagerTask'
            TaskPath            = '\Microsoft\Windows\SpacePort\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'SpeechModelDownloadTask'
        {
            TaskName            = 'SpeechModelDownloadTask'
            TaskPath            = '\Microsoft\Windows\Speech\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'Sqm-Tasks'
        {
            TaskName            = 'Sqm-Tasks'
            TaskPath            = '\Microsoft\Windows\PI\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'SR'
        {
            TaskName            = 'SR'
            TaskPath            = '\Microsoft\Windows\SystemRestore'
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

        ScheduledTask 'StartupAppTask'
        {
            TaskName            = 'StartupAppTask'
            TaskPath            = '\Microsoft\Windows\Application Experience'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'StorageSense'
        {
            TaskName            = 'StorageSense'
            TaskPath            = '\Microsoft\Windows\DiskFootprint\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'UninstallDeviceTask'
        {
            TaskName            = 'UninstallDeviceTask'
            TaskPath            = '\Microsoft\Windows\Bluetooth\'
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

        ScheduledTask 'Usb-Notifications'
        {
            TaskName            = 'Usb-Notifications'
            TaskPath            = '\Microsoft\Windows\USB\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'VerifyWinRE'
        {
            TaskName            = 'VerifyWinRE'
            TaskPath            = '\Microsoft\Windows\RecoveryEnvironment'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'WIM-Hash-Management'
        {
            TaskName            = 'WIM-Hash-Management'
            TaskPath            = '\Microsoft\Windows\WOF\'
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

        ScheduledTask 'UpdateLibrary'
        {
            TaskName            = 'UpdateLibrary'
            TaskPath            = '\Microsoft\Windows\Windows Media Sharing'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'WinSAT'
        {
            TaskName            = 'WinSAT'
            TaskPath            = '\Microsoft\Windows\Maintenance'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'WsSwapAssessmentTask'
        {
            TaskName            = 'WsSwapAssessmentTask'
            TaskPath            = '\Microsoft\Windows\Sysmain\'
            Enable              = $false
            Ensure              = 'Absent'
        }

        ScheduledTask 'XblGameSaveTask'
        {
            TaskName            = 'XblGameSaveTask'
            TaskPath            = '\Microsoft\XblGameSave'
            Enable              = $false
            Ensure              = 'Absent'
        }

        Registry 'DeleteUserAppContainersOnLogoff'
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'Dword'
            ValueData   = '1'
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

        Registry 'HibernateEnabled'
        {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power'
            Ensure      = 'Present'
            ValueName   = 'HibernateEnabled'
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

        Registry 'AllowStorageSenseGlobal'
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense'
            Ensure      = 'Present'
            ValueName   = 'AllowStorageSenseGlobal'
            ValueType   = 'DWORD'
            ValueData   = '0'
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

        Registry 'AllowCortana'
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure      = 'Present'
            ValueName   = 'AllowCortana'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        Registry 'NoAutoUpdate'
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure      = 'Present'
            ValueName   = 'NoAutoUpdate'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        Registry 'CEIPEnable'
        {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient\Windows'
            Ensure      = 'Present'
            ValueName   = 'CEIPEnable'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }
    }
}
