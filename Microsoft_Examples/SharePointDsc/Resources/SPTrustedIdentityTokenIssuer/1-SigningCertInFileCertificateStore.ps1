<#
.EXAMPLE
    This example deploys a trusted token issuer to the local farm.
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
            SPTrustedIdentityTokenIssuer SampleSPTrust
            {
                Name                         = 'Contoso'
                Description                  = 'Contoso'
                Realm                        = 'https://sharepoint.contoso.com'
                SignInUrl                    = 'https://adfs.contoso.com/adfs/ls/'
                IdentifierClaim              = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                ClaimsMappings               =  @(
                    MSFT_SPClaimTypeMapping{
                        Name = 'Email'
                        IncomingClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                    }
                    MSFT_SPClaimTypeMapping{
                        Name = 'Role'
                        IncomingClaimType = 'http://schemas.xmlsoap.org/ExternalSTSGroupType'
                        LocalClaimType = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                    }
                )
                SigningCertificateThumbPrint = 'F0D3D9D8E38C1D55A3CEF3AAD1C18AD6A90D5628'
                ClaimProviderName            = 'LDAPCP'
                ProviderSignOutUri           = 'https://adfs.contoso.com/adfs/ls/'
                Ensure                       = 'Present'
                PsDscRunAsCredential         = $SetupAccount
            }
        }
    }
