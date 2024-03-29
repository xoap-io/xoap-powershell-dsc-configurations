<#
.EXAMPLE
    This example gives admin access to the specified users for the local farm as well as
    all content databases in the local farm.
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
            SPShellAdmins ShellAdmins
            {
                IsSingleInstance = 'Yes'
                Members          = 'CONTOSO\user1', 'CONTOSO\user2'
                Databases        = @(
                    @(MSFT_SPDatabasePermissions {
                        Name = 'SharePoint_Content_1'
                        Members = 'CONTOSO\user2', 'CONTOSO\user3'
                    })
                    @(MSFT_SPDatabasePermissions {
                        Name = 'SharePoint_Content_2'
                        Members = 'CONTOSO\user3', 'CONTOSO\user4'
                    })
                )
            }
        }
    }
