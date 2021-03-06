<#PSScriptInfo
.VERSION 1.0.0
.GUID e1cbce56-1760-4208-b2dd-45cea4e87ab7
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT Copyright the DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/FileContentDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/FileContentDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module FileContentDsc

<#
    .DESCRIPTION
    Set the `ConnectionString` entry in the [Database] section to the password
    provided in the $Secret credential object in the file `c:\myapp\myapp.ini`.
#>
Configuration IniSettingsFile_SetSecretTextEntry_Config"
{
    param
    (
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $Secret
    )

    Import-DSCResource -ModuleName FileContentDsc

    Node localhost
    {
        IniSettingsFile SetConnectionString
        {
            Path    = 'c:\myapp\myapp.ini'
            Section = 'Database'
            Key     = 'ConnectionString'
            Type    = 'Secret'
            Secret  = $Secret
        }
    }
}
