# DSC Configuration: XOAP_SQLServer_Baseline
# Purpose: Applies security and performance baseline settings to an existing SQL Server instance.
# Prerequisites: SQL Server must be installed before applying this configuration.
#                SqlServerDsc module required: Install-Module SqlServerDsc -ModuleVersion '16.6.0'
# Note: Update InstanceName if not using default instance (MSSQLSERVER).
Configuration 'XOAP_SQLServer_Baseline'
{
    param(
        [Parameter(Mandatory)]
        [PSCredential]$SqlAdministratorCredential,
        [string]$InstanceName = 'MSSQLSERVER'
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'SqlServerDsc'          -ModuleVersion '16.6.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_SQLServer_Baseline'
    {
        # --- Service ---
        Service 'MSSQLSERVER'
        {
            Name        = $InstanceName
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Server configuration: Max memory (set to 80% of RAM — adjust as needed) ---
        SqlConfiguration 'MaxServerMemory'
        {
            ServerName     = $env:COMPUTERNAME
            InstanceName   = $InstanceName
            OptionName     = 'max server memory (MB)'
            OptionValue    = 8192
            RestartService = $false
            DependsOn      = '[Service]MSSQLSERVER'
        }

        # --- Server configuration: Max degree of parallelism ---
        SqlConfiguration 'MaxDOP'
        {
            ServerName     = $env:COMPUTERNAME
            InstanceName   = $InstanceName
            OptionName     = 'max degree of parallelism'
            OptionValue    = 4
            RestartService = $false
            DependsOn      = '[Service]MSSQLSERVER'
        }

        # --- Server configuration: Cost threshold for parallelism ---
        SqlConfiguration 'CostThresholdForParallelism'
        {
            ServerName     = $env:COMPUTERNAME
            InstanceName   = $InstanceName
            OptionName     = 'cost threshold for parallelism'
            OptionValue    = 50
            RestartService = $false
            DependsOn      = '[Service]MSSQLSERVER'
        }

        # --- Server configuration: Remote admin connections ---
        SqlConfiguration 'RemoteAdminConnections'
        {
            ServerName   = $env:COMPUTERNAME
            InstanceName = $InstanceName
            OptionName   = 'remote admin connections'
            OptionValue  = 1
            DependsOn    = '[Service]MSSQLSERVER'
        }

        # --- Security: Disable SA login ---
        SqlLogin 'DisableSA'
        {
            Ensure       = 'Present'
            ServerName   = $env:COMPUTERNAME
            InstanceName = $InstanceName
            Name         = 'sa'
            LoginType    = 'SqlLogin'
            Disabled     = $true
            DependsOn    = '[Service]MSSQLSERVER'
        }

        # --- Security: Windows auth mode only ---
        SqlServerConfiguration 'WindowsAuthMode'
        {
            ServerName   = $env:COMPUTERNAME
            InstanceName = $InstanceName
            OptionName   = 'authentication mode'
            OptionValue  = 0
            DependsOn    = '[Service]MSSQLSERVER'
        }

        # --- Security: Disable xp_cmdshell ---
        SqlConfiguration 'DisableXpCmdshell'
        {
            ServerName   = $env:COMPUTERNAME
            InstanceName = $InstanceName
            OptionName   = 'xp_cmdshell'
            OptionValue  = 0
            DependsOn    = '[Service]MSSQLSERVER'
        }

        # --- Security: Disable CLR ---
        SqlConfiguration 'DisableCLR'
        {
            ServerName   = $env:COMPUTERNAME
            InstanceName = $InstanceName
            OptionName   = 'clr enabled'
            OptionValue  = 0
            DependsOn    = '[Service]MSSQLSERVER'
        }

        # --- Security: Disable Ole Automation Procedures ---
        SqlConfiguration 'DisableOleAutomation'
        {
            ServerName   = $env:COMPUTERNAME
            InstanceName = $InstanceName
            OptionName   = 'Ole Automation Procedures'
            OptionValue  = 0
            DependsOn    = '[Service]MSSQLSERVER'
        }

        # --- Audit: Login auditing (failed and successful) ---
        SqlServerAudit 'LoginAudit'
        {
            ServerName       = $env:COMPUTERNAME
            InstanceName     = $InstanceName
            Name             = 'XOAP_LoginAudit'
            Ensure           = 'Present'
            AuditFilter      = ''
            OnFailure        = 'Continue'
            FilePath         = 'C:\SQLAudit'
            ReserveDiskSpace = $false
            DependsOn        = '[Service]MSSQLSERVER'
        }
    }
}
