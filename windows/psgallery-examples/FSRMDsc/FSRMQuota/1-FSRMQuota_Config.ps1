<#PSScriptInfo
.VERSION 1.0.0
.GUID 38c8407c-d12a-4c98-bbbc-96b7f8c697f3
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
    This configuration will assign an FSRM Quota to the path 'D:\Users', with a Hard Limit
    of 5GB and threshold percentages of 85 and 100. An e-mail action is bound to each threshold.
    An event action is also bound to the 85 percent threshold.
#>
Configuration FSRMQuota_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMQuota DUsers
        {
            Path                 = 'd:\Users'
            Description          = '5 GB Hard Limit'
            Ensure               = 'Present'
            Size                 = 5GB
            SoftLimit            = $false
            ThresholdPercentages = @( 85, 100 )
        } # End of FSRMQuota Resource

        FSRMQuotaAction DUsersEmail85
        {
            Path       = 'd:\Users'
            Percentage = 85
            Ensure     = 'Present'
            Type       = 'Email'
            Subject    = '[Quota Threshold]% quota threshold exceeded'
            Body       = 'User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server]. The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
            MailBCC    = ''
            MailCC     = 'fileserveradmins@contoso.com'
            MailTo     = '[Source Io Owner Email]'
            DependsOn  = "[FSRMQuota]DUsers"
        } # End of FSRMQuotaAction Resource

        FSRMQuotaAction DUsersEvent85
        {
            Path       = 'd:\Users'
            Percentage = 85
            Ensure     = 'Present'
            Type       = 'Event'
            Body       = 'User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server]. The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
            EventType  = 'Warning'
            DependsOn  = "[FSRMQuota]DUsers"
        } # End of FSRMQuotaAction Resource

        FSRMQuotaAction DUsersEmail100
        {
            Path       = 'd:\Users'
            Percentage = 100
            Ensure     = 'Present'
            Type       = 'Email'
            Subject    = '[Quota Threshold]% quota threshold exceeded'
            Body       = 'User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server]. The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
            MailBCC    = ''
            MailCC     = 'fileserveradmins@contoso.com'
            MailTo     = '[Source Io Owner Email]'
            DependsOn  = "[FSRMQuota]DUsers"
        } # End of FSRMQuotaAction Resource
    } # End of Node
} # End of Configuration
