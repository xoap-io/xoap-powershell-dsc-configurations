<#PSScriptInfo
.VERSION 1.0.0
.GUID c5aa6aff-cad0-45dc-a55c-6fd671574455
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
    This configuration will create a FSRM Yes/No Classification Property called Confidential.
#>
Configuration FSRMClassificationProperty_YesNo_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMClassificationProperty ConfidentialFiles
        {
            Name        = 'Confidential'
            Type        = 'YesNo'
            Description = 'Is this file a confidential file'
            Ensure      = 'Present'
        } # End of FSRMClassificationProperty Resource
    } # End of Node
} # End of Configuration
