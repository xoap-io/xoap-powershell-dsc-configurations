<#
    .SYNOPSIS
        A DSC configuration script to install PostgreSQL on a system.
#>
Configuration Example"
{
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
       }
    }
}
