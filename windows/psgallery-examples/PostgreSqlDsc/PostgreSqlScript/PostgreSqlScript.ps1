<#
    .SYNOPSIS
        A DSC configuration script to run a PostgreSQL script against a database.
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
        PostgreSqlScript ExampleSetting
        {
            DatabaseName = 'testdb1'
            SetFilePath  = 'c:\dev\set.sql'
            GetFilePath  = 'c:\dev\get.sql'
            TestFilePath = 'c:\dev\test.sql'
            Credential   = $PostgresAccount
        }
    }
}
