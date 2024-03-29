<#
.EXAMPLE
    This example deploys a SP Trusted Root Authority to the local farm.
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
            SPTrustedRootAuthority SampleRootAuthority
            {
                Name                  = 'Contoso'
                CertificateThumbprint = '770515261D1AB169057E246E0EE6431D557C3AFB'
                Ensure                = 'Present'
                PsDscRunAsCredential  = $SetupAccount
            }
        }
    }
