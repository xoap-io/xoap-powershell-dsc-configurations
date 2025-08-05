Configuration 'XOAP_W11_24H2_VDOT_Optimizer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Node 'XOAP_W11_24H2_VDOT_Optimizer'
    {
        # Disable unnecessary services (VDOT recommendations)
        Service 'DiagTrack' { Name = 'DiagTrack'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'WMPNetworkSvc' { Name = 'WMPNetworkSvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'MapsBroker' { Name = 'MapsBroker'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'RetailDemo' { Name = 'RetailDemo'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'XblAuthManager' { Name = 'XblAuthManager'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'XblGameSave' { Name = 'XblGameSave'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'XboxGipSvc' { Name = 'XboxGipSvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'XboxNetApiSvc' { Name = 'XboxNetApiSvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'WSearch' { Name = 'WSearch'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'WlanSvc' { Name = 'WlanSvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'WwanSvc' { Name = 'WwanSvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'lfsvc' { Name = 'lfsvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'upnphost' { Name = 'upnphost'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'SSDPSRV' { Name = 'SSDPSRV'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'PeerDistSvc' { Name = 'PeerDistSvc'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'TrkWks' { Name = 'TrkWks'; State = 'stopped'; StartupType = 'Disabled' }
        Service 'defragsvc' { Name = 'defragsvc'; State = 'stopped'; StartupType = 'Manual' }
        # ...add all other VDOT services as needed...

        # Remove unwanted Appx packages (VDOT recommendations)
        cAppxProvisionedPackage 'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.People_2021.2105.4.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c' { PackageName = 'Microsoft.SkypeApp_15.79.95.0_neutral_~_kzf8qxf38zg5c'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.YourPhone_1.21121.250.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.YourPhone_1.21121.250.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.ZuneMusic_2019.21102.11411.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.ZuneVideo_2019.21111.10511.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        # ...add all other VDOT Appx removals as needed...

        # Disable scheduled tasks (VDOT recommendations)
        ScheduledTask 'Consolidator' { TaskName = 'Consolidator'; TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'MapsToastTask' { TaskName = 'MapsToastTask'; TaskPath = '\Microsoft\Windows\Maps'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'FamilySafetyMonitor' { TaskName = 'FamilySafetyMonitor'; TaskPath = '\Microsoft\Windows\Shell'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'FamilySafetyRefreshTask' { TaskName = 'FamilySafetyRefreshTask'; TaskPath = '\Microsoft\Windows\Shell'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'File History (maintenance mode)' { TaskName = 'File History (maintenance mode)'; TaskPath = '\Microsoft\Windows\FileHistory'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'Notifications' { TaskName = 'Notifications'; TaskPath = '\Microsoft\Windows\Location'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'WinSAT' { TaskName = 'WinSAT'; TaskPath = '\Microsoft\Windows\Maintenance'; Enable = $false; Ensure = 'Absent' }
        # ...add all other VDOT scheduled tasks as needed...

        # Registry tweaks for performance, background apps, and visual effects
        # Disables background apps globally for better performance
        Registry 'DisableBackgroundApps' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            Ensure = 'Present'
            ValueName = 'LetAppsRunInBackground'
            ValueType = 'DWORD'
            ValueData = '2'
        }
        # Sets visual effects to best performance for new users
        Registry 'VisualFXSetting' {
            Key = 'HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            Ensure = 'Present'
            ValueName = 'VisualFXSetting'
            ValueType = 'DWORD'
            ValueData = '2'
        }
        # Disables Windows telemetry for privacy and performance
        Registry 'DisableTelemetry' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure = 'Present'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        # Disables Cortana for privacy and resource savings
        Registry 'DisableCortana' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure = 'Present'
            ValueName = 'AllowCortana'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        # ...add more registry tweaks from VDOT, each with a comment explaining its purpose...
        # Disables Windows tips and notifications
        Registry 'DisableWindowsTips' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            Ensure = 'Present'
            ValueName = 'DisableWindowsTips'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        # Disables lock screen spotlight
        Registry 'NoLockScreenSpotlight' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            Ensure = 'Present'
            ValueName = 'NoLockScreenSpotlight'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        # Disables automatic app updates
        Registry 'NoAutoUpdate' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            Ensure = 'Present'
            ValueName = 'NoAutoUpdate'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        # Disables background access for Photos, Skype, YourPhone
        Registry 'DisablePhotosBackgroundAccess' {
            Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe'
            Ensure = 'Present'
            ValueName = 'Disabled'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        Registry 'DisableSkypeBackgroundAccess' {
            Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c'
            Ensure = 'Present'
            ValueName = 'Disabled'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        Registry 'DisableYourPhoneBackgroundAccess' {
            Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe'
            Ensure = 'Present'
            ValueName = 'Disabled'
            ValueType = 'DWORD'
            ValueData = '1'
        }

        # Edge optimizations
        # Disables Edge first run experience for faster logon
        Registry 'EdgeOOBEDisable' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        # ...add more Edge optimizations, each with a comment explaining its purpose...
        # Disables Edge background mode
        Registry 'EdgeBackgroundMode' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'BackgroundModeEnabled'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        # Disables Edge auto-launch on sign-in
        Registry 'EdgeAutoLaunch' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'AutoLaunchProtocolsComponentEnabled'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        # Disables Edge product assistance notifications
        Registry 'EdgeProductAssistance' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'ShowRecommendations'
            ValueType = 'DWORD'
            ValueData = '0'
        }

        # Optionally remove OneDrive and IE11 payload (advanced)
        # Removes OneDrive (advanced optimization)
        cAppxProvisionedPackage 'Microsoft.OneDrive_21.230.1107.0002_neutral_~_8wekyb3d8bbwe' {
            PackageName = 'Microsoft.OneDrive_21.230.1107.0002_neutral_~_8wekyb3d8bbwe'
            Ensure = 'Absent'
        }
        # Removes Internet Explorer 11 (advanced optimization)
        Registry 'RemoveIE11' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Internet Explorer'
            Ensure = 'Present'
            ValueName = 'IsInstalled'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        # ...add DSC resources for removal if desired...
    }
}
