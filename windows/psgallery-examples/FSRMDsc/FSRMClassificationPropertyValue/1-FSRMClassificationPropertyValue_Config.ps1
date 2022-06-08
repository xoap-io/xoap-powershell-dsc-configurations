<#PSScriptInfo
.VERSION 1.0.0
.GUID c38478d7-f209-4a4a-9502-57351baea769
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
    This configuration will create a FSRM Classification Property Value called 'Public' assigned to
    the Classification Property called 'Privacy'.
#>
Configuration FSRMClassificationPropertyValue_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMClassificationPropertyValue PublicClasificationPropertyValue
        {
            Name         = 'Public'
            PropertyName = 'Privacy'
            Description  = 'Publically accessible files.'
            Ensure       = 'Present'
        } # End of FSRMClassificationPropertyValue Resource
    } # End of Node
} # End of Configuration
