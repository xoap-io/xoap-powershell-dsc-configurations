# DSC Configuration: XOAP_W11_23H2_VDOT_Optimizer
# Purpose: Configures VDOT optimizations for Windows 11 23H2 AVD session hosts.
Configuration 'XOAP_W11_23H2_VDOT_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node 'XOAP_W11_23H2_VDOT_Optimizer'
    {
        # Disable unnecessary services (VDOT recommendations)
        $services = @(
            'DiagTrack',
            'WMPNetworkSvc',
            'MapsBroker',
            'RetailDemo',
            'Fax',
            'lfsvc',
            'WSearch',
            'SysMain',
            'TrkWks',
            'SharedAccess',
            'CscService',
            'WpcMonSvc',
            'SensrSvc',
            'SSDPSRV',
            'upnphost',
            'VacSvc',
            'wcncsvc',
            'PeerDistSvc',
            'DusmSvc',
            'DPS',
            'WdiServiceHost',
            'WdiSystemHost',
            'FDResPub',
            'fdPHost',
            'XblAuthManager',
            'XblGameSave',
            'XboxNetApiSvc',
            'WerSvc',
            'defragsvc'
        )
        foreach ($svc in $services) {
            Service $svc {
                Name        = $svc
                State       = 'stopped'
                StartupType = 'Disabled'
            }
        }

        # Remove unwanted Appx packages (VDOT recommendations)
        $appxPackages = @(
            'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.GetHelp_10.2111.43421.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsAlarms_2021.2101.28.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsCalculator_2020.2103.8.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsCamera_2021.105.10.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe',
            'Microsoft.WindowsStore_22112.1401.2.0_neutral_~_8wekyb3d8bbwe'
        )
        foreach ($pkg in $appxPackages) {
            cAppxProvisionedPackage $pkg {
                PackageName = $pkg
                Ensure = 'Absent'
            }
        }

        # Disable scheduled tasks (VDOT recommendations)
        $scheduledTasks = @(
            @{Name='Consolidator';Path='\Microsoft\Windows\Customer Experience Improvement Program'},
            @{Name='MapsToastTask';Path='\Microsoft\Windows\Maps'},
            @{Name='AnalyzeSystem';Path='\Microsoft\Windows\Power Efficiency Diagnostics'},
            @{Name='RegIdleBackup';Path='\Microsoft\Windows\Registry'},
            @{Name='ResolutionHost';Path='\Microsoft\Windows\WDI'},
            @{Name='WinSAT';Path='\Microsoft\Windows\Maintenance'}
        )
        foreach ($task in $scheduledTasks) {
            ScheduledTask $($task.Name) {
                TaskName = $task.Name
                TaskPath = $task.Path
                Enable   = $false
                Ensure   = 'Absent'
            }
        }

        # Registry tweaks for performance, background apps, and visual effects
        # Disables background apps
        Registry 'DisableBackgroundApps' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            Ensure = 'Present'
            ValueName = 'LetAppsRunInBackground'
            ValueType = 'DWORD'
            ValueData = '2'
        }

        # Sets visual effects to best performance
        Registry 'VisualFXSetting' {
            Key = 'HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            Ensure = 'Present'
            ValueName = 'VisualFXSetting'
            ValueType = 'DWORD'
            ValueData = '2'
        }

        # Disables telemetry
        Registry 'DisableTelemetry' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure = 'Present'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # Disables Cortana
        Registry 'DisableCortana' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure = 'Present'
            ValueName = 'AllowCortana'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # Disables Windows tips
        Registry 'DisableWindowsTips' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure = 'Present'
            ValueName = 'DisableWindowsTips'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        # Disables consumer features
        Registry 'DisableConsumerFeatures' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            Ensure = 'Present'
            ValueName = 'DisableOSUpgrade'
            ValueType = 'DWORD'
            ValueData = '1'
        }

        # Edge optimizations
        # Disables Edge first run experience
        Registry 'EdgeOOBEDisable' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'DWORD'
            ValueData = '1'
        }

        # Disables Edge background services
        Registry 'EdgeBackgroundServices' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'BackgroundModeEnabled'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # Optionally remove OneDrive and IE11 payload (advanced)
        # Removes OneDrive
        Registry 'RemoveOneDrive' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
            Ensure = 'Present'
            ValueName = 'DisableFileSyncNGSC'
            ValueType = 'DWORD'
            ValueData = '1'
        }

        # Removes IE11
        Registry 'RemoveIE11' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Internet Explorer'
            Ensure = 'Present'
            ValueName = 'IsInstalled'
            ValueType = 'DWORD'
            ValueData = '0'
        }
    }
}
XOAP_W11_23H2_VDOT_Optimizer -OutputPath 'C:\DSC\XOAP_W11_23H2_VDOT_Optimizer'
