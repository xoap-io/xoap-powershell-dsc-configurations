# DSC Configuration: XOAP_AVD_W2K22_FSLogix
# Purpose: Configures FSLogix profile containers for Windows Server 2022 (AVD multi-session and RDS).
Configuration 'XOAP_AVD_W2K22_FSLogix'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_AVD_W2K22_FSLogix'
    {
        # FSLogix service
        Service 'FrxSvc'
        {
            Name        = 'frxsvc'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'FrxProxy'
        {
            Name        = 'frxProxy'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # FSLogix Profile Container: Enabled
        Registry 'FSLogix_Enabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix Profile Container: VHD location (update to your file share path)
        Registry 'FSLogix_VHDLocations'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'VHDLocations'
            ValueType = 'MultiString'
            ValueData = '\\fileserver\fslogix\profiles'
        }

        # FSLogix: Delete local profile on logoff
        Registry 'FSLogix_DeleteLocalProfileWhenVHDShouldApply'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'DeleteLocalProfileWhenVHDShouldApply'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix: Prevent login of users with failed profile
        Registry 'FSLogix_PreventLoginWithFailure'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'PreventLoginWithFailure'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix: Prevent login with temp profile
        Registry 'FSLogix_PreventLoginWithTempProfile'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'PreventLoginWithTempProfile'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix: VHD size in MB (30GB)
        Registry 'FSLogix_SizeInMBs'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'SizeInMBs'
            ValueType = 'Dword'
            ValueData = '30720'
        }

        # FSLogix: Disk compaction enabled
        Registry 'FSLogix_DiskCompaction'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'VolumeType'
            ValueType = 'String'
            ValueData = 'VHDX'
        }

        # FSLogix: Profile type = 0 (standard)
        Registry 'FSLogix_ProfileType'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'ProfileType'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # FSLogix Office Container: Enabled
        Registry 'FSLogix_Office_Enabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix\ODFC'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix Office Container: Include OneDrive
        Registry 'FSLogix_Office_IncludeOneDrive'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix\ODFC'
            Ensure    = 'Present'
            ValueName = 'IncludeOneDrive'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix Office Container: Include Outlook data
        Registry 'FSLogix_Office_IncludeOutlook'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix\ODFC'
            Ensure    = 'Present'
            ValueName = 'IncludeOutlook'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix: Concurrent user sessions (for multi-session)
        Registry 'FSLogix_ConcurrentUserSessions'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'ConcurrentUserSessions'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # FSLogix: Access network as computer object
        Registry 'FSLogix_AccessNetworkAsComputerObject'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix\Profiles'
            Ensure    = 'Present'
            ValueName = 'AccessNetworkAsComputerObject'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_AVD_W2K22_FSLogix -OutputPath 'C:\DSC\XOAP_AVD_W2K22_FSLogix'
