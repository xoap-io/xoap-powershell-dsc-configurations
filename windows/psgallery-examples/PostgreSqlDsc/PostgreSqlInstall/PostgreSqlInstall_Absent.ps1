<#
    .SYNOPSIS
        A DSC configuration script to remove PostgreSQL from a system.
#>
Configuration Example"
{
    Import-DscResource -ModuleName PostgreSqlDsc

    Node localhost
    {
        PostgreSqlInstall ExampleSetting
       {
            Ensure           = 'Absent'
            Version          = '12'
            InstallerPath    = 'C:\postgresql-12.4-1-windows-x64.exe'
       }
    }
}
