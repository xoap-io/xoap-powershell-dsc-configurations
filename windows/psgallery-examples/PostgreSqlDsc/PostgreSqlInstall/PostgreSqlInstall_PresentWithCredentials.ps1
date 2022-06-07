<#
    .SYNOPSIS
        A DSC configuration script to install PostgreSQL on a system without using a default super account
        or a default service account.
#>
Configuration Example"
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceAccount,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $SuperAccount
    )

    Import-DscResource -ModuleName PostgreSqlDsc

    Node localhost
    {
        PostgreSqlInstall ExampleSetting
       {
            Ensure           = 'Present'
            Version          = '12'
            InstallerPath    = 'C:\postgresql-12.4-1-windows-x64.exe'
            ServiceName      = 'postgreSql_RPS'
            InstallDirectory = 'C:\PostgreSQL'
            ServerPort       = '5432'
            DataDirectory    = 'C:\PostgreSQL\Data'
            Features         = 'commandlinetools','server','pgadmin','stackbuilder'
            ServiceAccount   = $ServiceAccount
            SuperAccount     = $SuperAccount

       }
    }
}
