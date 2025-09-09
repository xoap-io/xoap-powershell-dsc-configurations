<#PSScriptInfo
.VERSION 1.0.0
.GUID b89c5e83-74cf-4fac-a8f2-2441998ae750
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
    This configuration will create a FSRM Quota Template called '5 GB Hard Limit', with a
    Hard Limit of 5GB and threshold percentages of 85 and 100. An e-mail action is bound
    to each threshold. An event action is also bound to the 85 percent threshold.
#>
Configuration FSRMQuotaTemplateAction_Config
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMQuotaTemplate HardLimit5GB
        {
            Name                 = '5 GB Limit'
            Description          = '5 GB Hard Limit'
            Ensure               = 'Present'
            Size                 = 5GB
            SoftLimit            = $false
            ThresholdPercentages = @( 85, 100 )
        } # End of FSRMQuotaTemplate Resource

        FSRMQuotaTemplateAction HardLimit5GBEmail85
        {
            Name       = '5 GB Limit'
            Percentage = 85
            Ensure     = 'Present'
            Type       = 'Email'
            Subject    = '[Quota Threshold]% quota threshold exceeded'
            Body       = 'User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server]. The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
            MailBCC    = ''
            MailCC     = 'fileserveradmins@contoso.com'
            MailTo     = '[Source Io Owner Email]'
            DependsOn  = "[FSRMQuotaTemplate]HardLimit5GB"
        } # End of FSRMQuotaTemplateAction Resource

        FSRMQuotaTemplateAction HardLimit5GBEvent85
        {
            Name       = '5 GB Limit'
            Percentage = 85
            Ensure     = 'Present'
            Type       = 'Event'
            Body       = 'User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server]. The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
            EventType  = 'Warning'
            DependsOn  = "[FSRMQuotaTemplate]HardLimit5GB"
        } # End of FSRMQuotaTemplateAction Resource

        FSRMQuotaTemplateAction HardLimit5GBEmail100
        {
            Name       = '5 GB Limit'
            Percentage = 100
            Ensure     = 'Present'
            Type       = 'Email'
            Subject    = '[Quota Threshold]% quota threshold exceeded'
            Body       = 'User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server]. The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
            MailBCC    = ''
            MailCC     = 'fileserveradmins@contoso.com'
            MailTo     = '[Source Io Owner Email]'
            DependsOn  = "[FSRMQuotaTemplate]HardLimit5GB"
        } # End of FSRMQuotaTemplateAction Resource
    } # End of Node
} # End of Configuration
