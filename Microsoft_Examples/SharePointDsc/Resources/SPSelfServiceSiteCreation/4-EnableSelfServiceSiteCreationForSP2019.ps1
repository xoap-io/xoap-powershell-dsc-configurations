<#
.EXAMPLE
    This example shows how to configure self-service site creation with a custom form for a web application
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
            SPSelfServiceSiteCreation SSC
            {
                WebAppUrl             = 'http://example.contoso.local'
                Enabled               = $true
                ManagedPath           = 'sites'
                UserExperienceVersion = 'Modern'
                PsDscRunAsCredential  = $SetupAccount
            }
        }
    }
