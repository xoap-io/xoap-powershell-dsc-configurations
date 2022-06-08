<#PSScriptInfo
.VERSION 1.0.0
.GUID 676c644e-5fc9-4325-b25c-20cf42689bae
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
    This configuration will create a FSRM Classification Rule called 'Confidential' that
    will assign a Privacy value of Confidential to any files containing the text
    Confidential in the folder d:\users or any folder categorized as 'User Files'.
#>
Configuration FSRMClassificationRule_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMClassificationRule ConfidentialPrivacyClasificationRule
        {
            Name                    = 'Confidential'
            Description             = 'Set Confidential'
            Ensure                  = 'Present'
            Property                = 'Privacy'
            PropertyValue           = 'Confidential'
            ClassificationMechanism = ''
            ContentString           = 'Confidential'
            Namespace               = '[FolderUsage_MS=User Files]', 'd:\Users'
            ReevaluateProperty      = 'Overwrite'
        } # End of FSRMClassificationRule Resource
    } # End of Node
} # End of Configuration
