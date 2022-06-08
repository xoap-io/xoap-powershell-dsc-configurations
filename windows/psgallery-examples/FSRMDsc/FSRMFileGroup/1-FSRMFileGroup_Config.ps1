<#PSScriptInfo
.VERSION 1.0.0
.GUID 4ca93854-dec0-4762-89a0-623bc8c43380
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
    This configuration will create a FSRM File Group called 'Portable Document Files'.
#>
Configuration FSRMFileGroup_Config"
{
    Import-DscResource -Module FSRMDsc

    Node localhost
    {
        FSRMFileGroup FSRMFileGroupPortableFiles
        {
            Name           = 'Portable Document Files'
            Description    = 'Files containing portable document formats'
            Ensure         = 'Present'
            IncludePattern = '*.eps', '*.pdf', '*.xps'
        } # End of FSRMFileGroup Resource
    } # End of Node
} # End of Configuration
