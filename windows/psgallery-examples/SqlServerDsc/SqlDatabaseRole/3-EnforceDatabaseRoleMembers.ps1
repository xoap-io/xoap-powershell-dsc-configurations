<#
    .DESCRIPTION
        This example shows how to do the following:

        1. Ensure that the database role named ReportViewer is present in the
           AdventureWorks database on instance sqltest.company.local\DSC.
        2. Ensure that users CONTOSO\Barbara and CONTOSO\Fred will always be
           the only members of the role.
#>

Configuration Example"
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $SqlAdministratorCredential
    )

    Import-DscResource -ModuleName 'SqlServerDsc'

    node localhost
    {
        SqlDatabaseRole 'ReportViewer_EnforceRoleMembers'
        {
            ServerName           = 'sqltest.company.local'
            InstanceName         = 'DSC'
            DatabaseName         = 'AdventureWorks'
            Name                 = 'ReportViewer'
            Members              = @('CONTOSO\Barbara', 'CONTOSO\Fred')
            Ensure               = 'Present'

            PsDscRunAsCredential = $SqlAdministratorCredential
        }
    }
}
