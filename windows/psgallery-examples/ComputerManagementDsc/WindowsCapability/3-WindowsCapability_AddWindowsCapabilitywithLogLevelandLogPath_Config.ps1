<#PSScriptInfo
.VERSION 1.0.0
.GUID c966b525-2764-461e-b48e-b9f479c86a64
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT Copyright the DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/ComputerManagementDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/ComputerManagementDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module ComputerManagementDsc

<#
    .DESCRIPTION
        Example script that adds the Windows Capability OpenSSH.Client~~~~0.0.1.0
        and set the LogLevel to log Errors only and write the Logfile to Path C:\Temp.
#>
Configuration WindowsCapability_AddWindowsCapabilitywithLogLevelandLogPath_Config"
{
    Import-DSCResource -ModuleName ComputerManagementDsc

    Node localhost
    {
        WindowsCapability OpenSSHClient
        {
            Name     = 'OpenSSH.Client~~~~0.0.1.0'
            Ensure   = 'Present'
            LogLevel = 'Errors'
            LogPath  = 'C:\Temp\Logfile.log'
        }
    }
}
