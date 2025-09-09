Configuration RDS_Optimization_W2K19 {
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xRemoteDesktopSessionHost'
    Import-DscResource -ModuleName 'xRemoteDesktopSessionCollection'
    Import-DscResource -ModuleName 'xRemoteDesktopSessionDeployment'
    Import-DscResource -ModuleName 'xRegistry'
    Import-DscResource -ModuleName 'xSmbShare'

    Node localhost {
        # Create file server shares for UserProfiles and ProfileDisks
        File UserProfilesFolder {
            DestinationPath = 'C:\Shares\UserProfiles'
            Type            = 'Directory'
            Ensure          = 'Present'
        }
        xSmbShare UserProfilesShare {
            Name        = 'UserProfiles'
            Path        = 'C:\Shares\UserProfiles'
            Description = 'Roaming User Profiles'
            Ensure      = 'Present'
            FullAccess  = @('Domain Users')
            DependsOn   = '[File]UserProfilesFolder'
        }

        File ProfileDisksFolder {
            DestinationPath = 'C:\Shares\ProfileDisks'
            Type            = 'Directory'
            Ensure          = 'Present'
        }
        xSmbShare ProfileDisksShare {
            Name        = 'ProfileDisks'
            Path        = 'C:\Shares\ProfileDisks'
            Description = 'RDS Profile Disks'
            Ensure      = 'Present'
            FullAccess  = @('Domain Users')
            DependsOn   = '[File]ProfileDisksFolder'
        }

        # Configure roaming profiles and profile disk paths for RDS
        xRegistry RoamingProfilePath {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'ProfilePath'
            ValueData = '\\Computer\UserProfiles\%USERNAME%'
            ValueType = 'String'
            Ensure    = 'Present'
        }
        xRegistry ProfileDiskPath {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'UseProfilePathAsProfileDiskPath'
            ValueData = 0
            ValueType = 'Dword'
            Ensure    = 'Present'
        }
        xRegistry ProfileDiskSharePath {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'ProfileDiskPath'
            ValueData = '\\Computer\ProfileDisks'
            ValueType = 'String'
            Ensure    = 'Present'
        }
    }
}

# To apply, run:
# RDS_Optimization_W2K19 -OutputPath C:\DSC\RDS_Optimization_W2K19
# Start-DscConfiguration -Path C:\DSC\RDS_Optimization_W2K19 -Wait -Verbose
