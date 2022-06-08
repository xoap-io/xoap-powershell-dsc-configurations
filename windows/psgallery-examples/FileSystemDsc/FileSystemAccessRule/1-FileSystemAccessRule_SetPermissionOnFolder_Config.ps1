<#PSScriptInfo
.VERSION 1.0.0
.GUID e479ea7f-0427-40a5-96ab-17215511b05f
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/FileSystemDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/FileSystemDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.RELEASENOTES
First release.
#>

#Requires -Module FileSystemDsc

<#
    .DESCRIPTION
        This configuration will add the full control right to the folder
        'C:\some\path' for the identity NT AUTHORITY\NETWORK SERVICE, and
        add the read right to the folder 'C:\other\path' for the local group
        Users.
#>
Configuration FileSystemAccessRule_SetPermissionOnFolder_Config"
{
    Import-DscResource -ModuleName FileSystemDsc

    node localhost
    {
        FileSystemAccessRule 'AddRightFullControl'
        {
            Path = 'C:\some\path'
            Identity = 'NT AUTHORITY\NETWORK SERVICE'
            Rights = @('FullControl')
        }

        FileSystemAccessRule 'AddRightRead'
        {
            Path = 'C:\other\path'
            Identity = 'Users'
            Rights = @('Read')
        }
    }
}
