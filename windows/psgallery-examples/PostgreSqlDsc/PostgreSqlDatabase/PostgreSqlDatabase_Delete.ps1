<#
    .SYNOPSIS
        A DSC configuration script to delete a database in PostgreSql.
#>
Configuration Example"
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $PostgresAccount
    )

    Import-DscResource -ModuleName PostgreSqlDsc

    Node localhost
    {
        PostgreSqlDatabase ExampleSetting
        {
            Ensure       = 'Absent'
            DatabaseName = 'testdb1'
            Credential   = $PostgresAccount
        }
    }
}
