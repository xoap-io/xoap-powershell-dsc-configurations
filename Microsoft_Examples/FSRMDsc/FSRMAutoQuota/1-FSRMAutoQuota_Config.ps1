<#PSScriptInfo
.VERSION 1.0.0
.GUID 39ff861a-331d-4605-aac9-5a773dde4ec9
.AUTHOR Daniel Scott-Raynsford
.COMPANYNAME
.COPYRIGHT (c) 2018 Daniel Scott-Raynsford. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PlagueHO/FSRMDsc/blob/master/LICENSE
.PROJECTURI https://github.com/PlagueHO/FSRMDsc
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
    This configuration will assign an FSRM Auto Quota to the path 'd:\users' using the
    template '5 GB Limit'.
#>
Configuration FSRMAutoQuota_Config
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMAutoQuota DUsers
        {
            Path     = 'd:\Users'
            Ensure   = 'Present'
            Disabled = $false
            Template = '5 GB Limit'
        } # End of FSRMAutoQuota Resource
    } # End of Node
} # End of Configuration
