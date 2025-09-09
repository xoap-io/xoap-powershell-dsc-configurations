Configuration 'XOAP_W11_2009_Citrix_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'
    Import-DscResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
    Import-DscResource -ModuleName 'XOAPAppxPackageDSC' -ModuleVersion '0.1.0'

    Node 'XOAP_W11_2009_Citrix_Optimizer'
    {
        # Disable unnecessary services
        $services = @(
            'AJRouter',
            'ALG',
            'BthAvctpSvc',
            'BDESVC',
            'wbengine',
            'BTAGService',
            'bthserv',
            'PeerDistSvc',
            'DusmSvc',
            'DPS',
            'WdiServiceHost',
            'WdiSystemHost',
            'TrkWks',
            'MapsBroker',
            'EFS',
            'fdPHost',
            'FDResPub',
            'lfsvc',
            'SharedAccess',
            'CscService',
            'WpcMonSvc',
            'RetailDemo',
            'SensrSvc',
            'SSDPSRV',
            'upnphost',
            'VacSvc',
            'wcncsvc',
            'WMPNetworkSvc',
            'icssvc',
            'WlanSvc',
            'WwanSvc',
            'XboxGipSvc',
            'XblAuthManager',
            'XblGameSave',
            'XboxNetApiSvc',
            'SysMain',
            'WerSvc',
            'WSearch'
        )
        foreach ($svc in $services) {
            Service $svc {
                Name        = $svc
                State       = 'stopped'
                StartupType = 'Disabled'
            }
        }

        # Set defragsvc to Manual
        Service 'defragsvc' {
            Name        = 'defragsvc'
            State       = 'stopped'
            StartupType = 'Manual'
        }

        # Remove unnecessary Appx provisioned packages
        $appxPackages = @(
            'Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.DesktopAppInstaller_2021.1207.634.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.GetHelp_10.2111.43421.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.Getstarted_2021.2111.2.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.HEIFImageExtension_1.0.43012.0_x64__8wekyb3d8bbwe',
            'Microsoft.Microsoft3DViewer_2021.2107.7012.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.MicrosoftOfficeHub_18.2110.13110.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.MicrosoftSolitaireCollection_4.12.1050.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.MicrosoftStickyNotes_4.2.2.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.MixedReality.Portal_2000.21051.1282.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.MSPaint_2021.2105.4017.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.Office.OneNote_16001.14326.20674.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.ScreenSketch_2020.814.2355.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c',
            'Microsoft.StorePurchaseApp_12109.1001.10.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.VP9VideoExtensions_1.0.42791.0_x64__8wekyb3d8bbwe',
            'Microsoft.Wallet_2.4.18324.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WebMediaExtensions_1.0.42192.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WebpImageExtension_1.0.42351.0_x64__8wekyb3d8bbwe',
            'Microsoft.Windows.Photos_2021.21090.10008.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsCalculator_2020.2103.8.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsCamera_2021.105.10.0_neutral_~_8wekyb3d8bbwe',
            'microsoft.windowscommunicationsapps_16005.14326.20544.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsFeedbackHub_2022.106.2230.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsStore_22112.1401.2.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.Xbox.TCUI_1.24.10001.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.XboxGameOverlay_1.54.4001.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.XboxGamingOverlay_5.721.12013.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.XboxIdentityProvider_12.83.12001.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.XboxSpeechToTextOverlay_1.21.13002.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.YourPhone_1.21121.250.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe'
        )
        foreach ($pkg in $appxPackages) {
            cAppxProvisionedPackage $pkg {
                PackageName = $pkg
                Ensure = 'Absent'
            }
        }

        # Remove unnecessary scheduled tasks
        $scheduledTasks = @(
            @{Name='AnalyzeSystem';Path='\Microsoft\Windows\Power Efficiency Diagnostics'},
            @{Name='BfeOnServiceStartTypeChange';Path='\Microsoft\Windows\Windows Filtering Platform'},
            @{Name='Cellular';Path='\Microsoft\Windows\Management\Provisioning\'},
            @{Name='Consolidator';Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='Diagnostics';Path='\Microsoft\Windows\DiskFootprint\'},
            @{Name='FamilySafetyMonitor';Path='\Microsoft\Windows\Shell'},
            @{Name='FamilySafetyRefreshTask';Path='\Microsoft\Windows\Shell'},
            @{Name='File History (maintenance mode)';Path='\Microsoft\Windows\FileHistory'},
            @{Name='WindowsActionDialog';Path='\Microsoft\Windows\Location'},
            @{Name='Notifications';Path='\Microsoft\Windows\Location'},
            @{Name='MapsToastTask';Path='\Microsoft\Windows\Maps'},
            @{Name='MapsUpdateTask';Path='\Microsoft\Windows\Maps'},
            @{Name='Microsoft Compatibility Appraiser';Path='\Microsoft\Windows\Application Experience'},
            @{Name='Microsoft-Windows-DiskDiagnosticDataCollector';Path='\Microsoft\Windows\DiskDiagnostic'},
            @{Name='Microsoft-Windows-DiskDiagnosticResolver';Path='\Microsoft\Windows\DiskDiagnostic'},
            @{Name='MNO Metadata Parser';Path='\Microsoft\Windows\Mobile Broadband Accounts'},
            @{Name='NotificationTask';Path='\Microsoft\Windows\WwanSvc\'},
            @{Name='ProactiveScan';Path='\Microsoft\Windows\CHKDSK'},
            @{Name='ProcessMemoryDiagnosticEvents';Path='\Microsoft\Windows\MemoryDiagnostic'},
            @{Name='ProgramDataUpdater';Path='\Microsoft\Windows\Application Experience'},
            @{Name='Proxy';Path='\Microsoft\Windows\Autochk'},
            @{Name='RecommendedTroubleshootingScanner';Path='\Microsoft\Windows\Diagnosis\'},
            @{Name='ReconcileFeatures';Path='\Microsoft\Windows\Flighting\FeatureConfig\'},
            @{Name='ReconcileLanguageResources';Path='\Microsoft\Windows\LanguageComponentsInstaller\'},
            @{Name='RefreshCache';Path='\Microsoft\Windows\Flighting\OneSettings\'},
            @{Name='RegIdleBackup';Path='\Microsoft\Windows\Registry'},
            @{Name='ResolutionHost';Path='\Microsoft\Windows\WDI'},
            @{Name='ResPriStaticDbSync';Path='\Microsoft\Windows\Sysmain\'},
            @{Name='RunFullMemoryDiagnostic';Path='\Microsoft\Windows\MemoryDiagnostic'},
            @{Name='ScanForUpdates';Path='\Microsoft\Windows\InstallService\'},
            @{Name='ScanForUpdatesAsUser';Path='\Microsoft\Windows\InstallService\'},
            @{Name='Scheduled';Path='\Microsoft\Windows\Diagnosis'},
            @{Name='ScheduledDefrag';Path='\Microsoft\Windows\Defrag'},
            @{Name='SilentCleanup';Path='\Microsoft\Windows\DiskCleanup\'},
            @{Name='SmartRetry';Path='\Microsoft\Windows\InstallService\'},
            @{Name='SpaceAgentTask';Path='\Microsoft\Windows\SpacePort\'},
            @{Name='SpaceManagerTask';Path='\Microsoft\Windows\SpacePort\'},
            @{Name='SpeechModelDownloadTask';Path='\Microsoft\Windows\Speech\'},
            @{Name='Sqm-Tasks';Path='\Microsoft\Windows\PI\'},
            @{Name='SR';Path='\Microsoft\Windows\SystemRestore'},
            @{Name='StartComponentCleanup';Path='\Microsoft\Windows\Servicing'},
            @{Name='StartupAppTask';Path='\Microsoft\Windows\Application Experience'},
            @{Name='StorageSense';Path='\Microsoft\Windows\DiskFootprint\'},
            @{Name='UninstallDeviceTask';Path='\Microsoft\Windows\Bluetooth\'},
            @{Name='UsbCeip';Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='Usb-Notifications';Path='\Microsoft\Windows\USB\'},
            @{Name='VerifyWinRE';Path='\Microsoft\Windows\RecoveryEnvironment'},
            @{Name='WIM-Hash-Management';Path='\Microsoft\Windows\WOF\'},
            @{Name='QueueReporting';Path='\Microsoft\Windows\Windows Error Reporting'},
            @{Name='UpdateLibrary';Path='\Microsoft\Windows\Windows Media Sharing'},
            @{Name='WinSAT';Path='\Microsoft\Windows\Maintenance'},
            @{Name='WsSwapAssessmentTask';Path='\Microsoft\Windows\Sysmain\'},
            @{Name='XblGameSaveTask';Path='\Microsoft\XblGameSave'}
        )
        foreach ($task in $scheduledTasks) {
            ScheduledTask $($task.Name) {
                TaskName = $task.Name
                TaskPath = $task.Path
                Enable   = $false
                Ensure   = 'Absent'
            }
        }

        # Registry optimizations
        # Ensures user app containers are deleted on logoff for improved security
        Registry 'DeleteUserAppContainersOnLogoff' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
            Ensure      = 'Present'
            ValueName   = 'DeleteUserAppContainersOnLogoff'
            ValueType   = 'Dword'
            ValueData   = '1'
        }

        # Disables automatic layout adjustments for desktop icons
        Registry 'EnableAutoLayout' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout'
            Ensure      = 'Present'
            ValueName   = 'EnableAutoLayout'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Disables boot optimization to reduce unnecessary disk activity
        Registry 'Enable' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction'
            Ensure      = 'Present'
            ValueName   = 'Enable'
            ValueType   = 'String'
            ValueData   = 'N'
        }

        # Disables screensaver for the default user profile
        Registry 'ScreenSaveActive' {
            Key         = 'HKEY_USERS\.DEFAULT\Control Panel\Desktop'
            Ensure      = 'Present'
            ValueName   = 'ScreenSaveActive'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Disables hibernation to save disk space and improve performance
        Registry 'HibernateEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power'
            Ensure      = 'Present'
            ValueName   = 'HibernateEnabled'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Disables crash dump creation to save disk space
        Registry 'CrashDumpEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl'
            Ensure      = 'Present'
            ValueName   = 'CrashDumpEnabled'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Disables Storage Sense globally
        Registry 'AllowStorageSenseGlobal' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense'
            Ensure      = 'Present'
            ValueName   = 'AllowStorageSenseGlobal'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Disables first logon animation for faster login experience
        Registry 'EnableFirstLogonAnimation' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Ensure      = 'Present'
            ValueName   = 'EnableFirstLogonAnimation'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Sets error mode to suppress system error dialogs
        Registry 'ErrorMode' {
            Key         = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows'
            Ensure      = 'Present'
            ValueName   = 'ErrorMode'
            ValueType   = 'DWORD'
            ValueData   = '2'
        }

        # Disables Cortana for privacy and performance
        Registry 'AllowCortana' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure      = 'Present'
            ValueName   = 'AllowCortana'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }

        # Disables automatic Windows Updates for better control
        Registry 'NoAutoUpdate' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure      = 'Present'
            ValueName   = 'NoAutoUpdate'
            ValueType   = 'DWORD'
            ValueData   = '1'
        }

        # Disables Customer Experience Improvement Program (CEIP)
        Registry 'CEIPEnable' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient\Windows'
            Ensure      = 'Present'
            ValueName   = 'CEIPEnable'
            ValueType   = 'DWORD'
            ValueData   = '0'
        }
    }
}
