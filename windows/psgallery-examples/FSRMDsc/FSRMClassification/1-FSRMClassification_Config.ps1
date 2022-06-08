<#PSScriptInfo
.VERSION 1.0.0
.GUID 87303cbb-e1bc-4b3d-b4da-d21e2f2f4af9
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
    This will configure the FSRM Classification settings on this server.
    It enables Continous Mode, Logging and sets the maximum Log size to 2 MB.
    The Classification schedule is also set to Monday through Wednesday at 11:30pm
    and will run a maximum of 4 hours.
#>
Configuration FSRMClassification_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMClassification FSRMClassificationSettings
        {
            Id                  = 'Default'
            Continuous          = $true
            ContinuousLog       = $true
            ContinuousLogSize   = 2048
            ScheduleWeekly      = 'Monday', 'Tuesday', 'Wednesday'
            ScheduleRunDuration = 4
            ScheduleTime        = '23:30'
        } # End of FSRMClassification Resource
    } # End of Node
} # End of Configuration
