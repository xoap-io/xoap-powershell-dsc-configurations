<#PSScriptInfo
.VERSION 1.0.0
.GUID b56be742-6e5c-4347-ac24-86fcb0e5931f
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
    This configuration will configure the FSRM Settings on a server.
#>
Configuration FSRMSettings_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMSettings FSRMSettings
        {
            IsSingleInstance         = 'Yes'
            SmtpServer               = 'smtp.contoso.com'
            AdminEmailAddress        = 'fsadmin@contoso.com'
            FromEmailAddress         = 'fsuser@contoso.com'
            CommandNotificationLimit = 90
            EmailNotificationLimit   = 90
            EventNotificationLimit   = 90
        } # End of FSRMSettings Resource
    } # End of Node
} # End of Configuration
