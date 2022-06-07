<#PSScriptInfo
.VERSION 1.0.0
.GUID dfbe101b-d765-47d4-9629-ff2a2ac0ef51
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
    This configuration will assign the 'Block Some Files' file screen template to the
    path 'D:\Users'. It will also force the File Screen assigned to this path to
    exactly match the 'Block Some Files' template. Any changes to the actions, include
    groups or active setting on the File Screen assigned to this path will cause
    the File Screen to be removed and reapplied.
#>
Configuration FSRMFileScreenAction_UsingTemplate_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMFileScreen DUsersFileScreens
        {
            Path            = 'd:\users'
            Description     = 'File Screen for Blocking Some Files'
            Ensure          = 'Present'
            Template        = 'Block Some Files'
            MatchesTemplate = $true
        } # End of FSRMFileScreen Resource
    } # End of Node
} # End of Configuration
