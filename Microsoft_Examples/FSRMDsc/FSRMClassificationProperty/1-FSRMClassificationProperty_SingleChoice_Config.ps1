<#PSScriptInfo
.VERSION 1.0.0
.GUID 014b9323-6d04-44cd-bd28-63f5de78cbdc
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
    This configuration will create a FSRM Single Choice Classification Property called Privacy.
#>
Configuration FSRMClassificationProperty_SingleChoice_Config
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMClassificationProperty PrivacyClasificationProperty
        {
            Name          = 'Privacy'
            Type          = 'SingleChoice'
            DisplayName   = 'File Privacy'
            Description   = 'File Privacy Property'
            Ensure        = 'Present'
            PossibleValue = 'Top Secret', 'Secret', 'Confidential'
        } # End of FSRMClassificationProperty Resource
    } # End of Node
} # End of Configuration
