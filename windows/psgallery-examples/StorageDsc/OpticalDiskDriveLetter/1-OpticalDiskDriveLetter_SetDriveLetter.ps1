<#PSScriptInfo
.VERSION 1.0.0
.GUID 1ef469e5-eabf-4e5d-9ff4-f17d2894991f
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT Copyright the DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/StorageDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/StorageDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module StorageDsc

<#
    .DESCRIPTION
        This configuration will set the drive letter of the first
        optical disk drive in the system to 'Z'.
#>
Configuration OpticalDiskDriveLetter_SetDriveLetter"
{
    Import-DSCResource -ModuleName StorageDsc

    Node localhost
    {
        OpticalDiskDriveLetter SetFirstOpticalDiskDriveLetterToZ
        {
            DiskId      = 1
            DriveLetter = 'Z'
        }
    }
}
