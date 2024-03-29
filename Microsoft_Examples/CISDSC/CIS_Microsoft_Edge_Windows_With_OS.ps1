#Requires -module CISDSC
#Requires -RunAsAdministrator

<#
    .DESCRIPTION
    Applies CIS Level one benchmarks for Microsoft Edge with no exclusions on Windows.
    Exclusion documentation can be found in the docs folder of this module.
    This will also include CIS benchmarks for the Windows OS.
#>

Configuration OS_and_Microsoft_Edge_CIS_L1
{
    Import-DSCResource -ModuleName 'CISDSC'

    node 'localhost'
    {
        # CIS_Microsoft_Windows_10_Enterprise_Release_20H2 is used for example purposes. Use the resource applicable to your system's build.
        CIS_Microsoft_Windows_10_Enterprise_Release_20H2 'System CISBenchmarks'
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

        CIS_Microsoft_Edge_Windows 'Microsoft Edge CISBenchmarks'
        {
        }
    }
}

OS_and_Microsoft_Edge_CIS_L1
Start-DscConfiguration -Path '.\OS_and_Microsoft_Edge_CIS_L1' -Verbose -Wait

