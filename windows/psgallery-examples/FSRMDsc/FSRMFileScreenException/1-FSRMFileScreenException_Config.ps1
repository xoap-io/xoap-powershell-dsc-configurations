<#PSScriptInfo
.VERSION 1.0.0
.GUID f6bd598e-c87d-41a7-846d-56b39bc76197
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT Copyright the DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/FSRMDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/FSRMDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module FSRMDsc

<#
    .DESCRIPTION
    This configuration add a File Screen Exception that Includes 'E-mail Files' to
    the path 'D:\Users'.
#>
Configuration FSRMFileScreenException_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMFileScreenException DUsersFileScreenException
        {
            Path         = 'd:\users'
            Description  = 'File Screen for Blocking Some Files'
            Ensure       = 'Present'
            IncludeGroup = 'E-mail Files'
        } # End of FSRMFileScreenException Resource
    } # End of Node
} # End of Configuration
