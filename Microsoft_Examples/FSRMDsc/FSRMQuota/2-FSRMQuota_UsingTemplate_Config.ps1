<#PSScriptInfo
.VERSION 1.0.0
.GUID 4e1a73f2-c37d-4022-b76a-ceb064f954ce
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
    This configuration will assign the '100 MB Limit' template to the path 'D:\Users'.
    It will also force the quota assigned to this path to exactly match the '100 MB Limit'
    template. Any changes to the thresholds or actions on the quota assigned to this path
    will cause the template to be removed and reapplied.
#>
Configuration FSRMQuota_UsingTemplate_Config
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMQuota DUsers
        {
            Path            = 'd:\Users'
            Description     = '100 MB Limit'
            Ensure          = 'Present'
            Template        = '100 MB Limit'
            MatchesTemplate = $true
        } # End of FSRMQuota Resource
    } # End of Node
} # End of Configuration
