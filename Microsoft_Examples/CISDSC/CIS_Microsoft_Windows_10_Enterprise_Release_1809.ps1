#Requires -module CISDSC
#Requires -RunAsAdministrator

<#
    .DESCRIPTION
    Applies CIS Level one benchmarks for Windows 10 build 1809 with no exclusions.
    Exclusion documentation can be found in the docs folder of this module.
#>

Configuration Win10_1809_L1
{
    Import-DSCResource -ModuleName 'CISDSC' -Name 'CIS_Microsoft_Windows_10_Enterprise_Release_1809'

    node 'localhost'
    {
        CIS_Microsoft_Windows_10_Enterprise_Release_1809 'CIS Benchmarks'
        {
            cis2315AccountsRenameadministratoraccount = 'CISAdmin'
            cis2316AccountsRenameguestaccount = 'CISGuest'
            cis2376LegalNoticeCaption = 'Legal Notice'
            cis2375LegalNoticeText = @'
This is a super secure device that we don't want bad people using.
I'm even making sure to put this as a literal string so that I can cleanly
use multiple lines to tell you how super secure it is.
'@
        }
    }
}

Win10_1809_L1
Start-DscConfiguration -Path '.\Win10_1809_L1'-Verbose -Wait