<#PSScriptInfo
.VERSION 1.0.0
.GUID d80823d5-59cb-4a41-b1a2-8afcd1a8408e
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
    This configuration will assign an Active FSRM File Screen to the path 'D:\Users'
    with three include groups. An e-mail and event action is bound to the File Screen.
#>
Configuration FSRMFileScreen_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMFileScreen DUsersFileScreen
        {
            Path         = 'd:\users'
            Description  = 'File Screen for Blocking Some Files'
            Ensure       = 'Present'
            Active       = $true
            IncludeGroup = 'Audio and Video Files', 'Executable Files', 'Backup Files'
        } # End of FSRMFileScreen Resource

        FSRMFileScreenAction DUsersFileScreenSomeFilesEmail
        {
            Path      = 'd:\users'
            Ensure    = 'Present'
            Type      = 'Email'
            Subject   = 'Unauthorized file matching [Violated File Group] file group detected'
            Body      = 'The system detected that user [Source Io Owner] attempted to save [Source File Path] on [File Screen Path] on server [Server]. This file matches the [Violated File Group] file group which is not permitted on the system.'
            MailBCC   = ''
            MailCC    = 'fileserveradmins@contoso.com'
            MailTo    = '[Source Io Owner Email]'
            DependsOn = "[FSRMFileScreen]DUsersFileScreen"
        } # End of FSRMFileScreenAction Resource

        FSRMFileScreenAction DUsersFileScreenSomeFilesEvent
        {
            Path      = 'd:\users'
            Ensure    = 'Present'
            Type      = 'Event'
            Body      = 'The system detected that user [Source Io Owner] attempted to save [Source File Path] on [File Screen Path] on server [Server]. This file matches the [Violated File Group] file group which is not permitted on the system.'
            EventType = 'Warning'
            DependsOn = "[FSRMFileScreen]DUsersFileScreen"
        } # End of FSRMFileScreenAction Resource
    } # End of Node
} # End of Configuration
