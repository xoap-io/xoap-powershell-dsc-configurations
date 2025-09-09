<#PSScriptInfo
.VERSION 1.0.0
.GUID 62b85bd2-3049-4db7-8313-aa0d829c7db9
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
    This configuration will create an Active FSRM File Screen Template called 'Block Some Files',
    with three include groups. An e-mail and event action is bound to the File Screen Template.
#>
Configuration FSRMFileScreenTemplateAction_Config
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMFileScreenTemplate FileScreenSomeFiles
        {
            Name         = 'Block Some Files'
            Description  = 'File Screen for Blocking Some Files'
            Ensure       = 'Present'
            Active       = $true
            IncludeGroup = 'Audio and Video Files', 'Executable Files', 'Backup Files'
        } # End of FSRMFileScreenTemplate Resource

        FSRMFileScreenTemplateAction FileScreenSomeFilesEmail
        {
            Name      = 'Block Some Files'
            Ensure    = 'Present'
            Type      = 'Email'
            Subject   = 'Unauthorized file matching [Violated File Group] file group detected'
            Body      = 'The system detected that user [Source Io Owner] attempted to save [Source File Path] on [File Screen Path] on server [Server]. This file matches the [Violated File Group] file group which is not permitted on the system.'
            MailBCC   = ''
            MailCC    = 'fileserveradmins@contoso.com'
            MailTo    = '[Source Io Owner Email]'
            DependsOn = "[FSRMFileScreenTemplate]FileScreenSomeFiles"
        } # End of FSRMFileScreenTemplateAction Resource

        FSRMFileScreenTemplateAction FileScreenSomeFilesEvent
        {
            Name      = 'Block Some Files'
            Ensure    = 'Present'
            Type      = 'Event'
            Body      = 'The system detected that user [Source Io Owner] attempted to save [Source File Path] on [File Screen Path] on server [Server]. This file matches the [Violated File Group] file group which is not permitted on the system.'
            EventType = 'Warning'
            DependsOn = "[FSRMFileScreenTemplate]FileScreenSomeFiles"
        } # End of FSRMFileScreenTemplateAction Resource
    } # End of Node
} # End of Configuration
