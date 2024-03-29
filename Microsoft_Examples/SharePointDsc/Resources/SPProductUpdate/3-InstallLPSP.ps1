<#
.EXAMPLE
    This example installs the SharePoint 2013 Dutch Language Pack Service Pack only in the specified window.
    It also shuts down services to speed up the installation process.
#>

    Configuration Example 
    {
        param(
            [Parameter(Mandatory = $true)]
            [PSCredential]
            $SetupAccount
        )
        Import-DscResource -ModuleName SharePointDsc

        node localhost {
            SPProductUpdate InstallCUMay2016
            {
                SetupFile            = 'C:\Install\SP2013-LP_NL-SP1\serverlpksp2013-kb2880554-fullfile-x64-nl-nl.exe'
                ShutdownServices     = $true
                BinaryInstallDays    = 'sat', 'sun'
                BinaryInstallTime    = '12:00am to 2:00am'
                Ensure               = 'Present'
                PsDscRunAsCredential = $SetupAccount
            }
        }
    }
