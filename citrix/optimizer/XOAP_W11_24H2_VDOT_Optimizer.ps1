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
        # ...add more services as per VDOT recommendations...

        # Remove unwanted Appx packages (VDOT recommendations)
        cAppxProvisionedPackage 'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.XboxApp_48.78.15001.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        cAppxProvisionedPackage 'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe' { PackageName = 'Microsoft.WindowsMaps_2021.2104.2.0_neutral_~_8wekyb3d8bbwe'; Ensure = 'Absent' }
        # ...add more Appx removals as per VDOT...

        # Disable scheduled tasks (VDOT recommendations)
        ScheduledTask 'Consolidator' { TaskName = 'Consolidator'; TaskPath = '\Microsoft\Windows\Customer Experience Improvement Program'; Enable = $false; Ensure = 'Absent' }
        ScheduledTask 'MapsToastTask' { TaskName = 'MapsToastTask'; TaskPath = '\Microsoft\Windows\Maps'; Enable = $false; Ensure = 'Absent' }
        # ...add more scheduled tasks...

        # Registry tweaks for performance, background apps, and visual effects
        Registry 'DisableBackgroundApps' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            Ensure = 'Present'
            ValueName = 'LetAppsRunInBackground'
            ValueType = 'DWORD'
            ValueData = '2'
        }
        Registry 'VisualFXSetting' {
            Key = 'HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
            Ensure = 'Present'
            ValueName = 'VisualFXSetting'
            ValueType = 'DWORD'
            ValueData = '2'
        }
        Registry 'DisableTelemetry' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure = 'Present'
            ValueName = 'AllowTelemetry'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        Registry 'DisableCortana' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure = 'Present'
            ValueName = 'AllowCortana'
            ValueType = 'DWORD'
            ValueData = '0'
        }
        # ...add more registry tweaks from VDOT...

        # Edge optimizations
        Registry 'EdgeOOBEDisable' {
            Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'DWORD'
            ValueData = '1'
        }
        # ...add more Edge optimizations...

        # Optionally remove OneDrive and IE11 payload (advanced)
        # ...add DSC resources for removal if desired...
    }
}
