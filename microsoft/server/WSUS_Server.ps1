

# DSC Configuration: WSUS_Server
# Purpose: Installs and configures WSUS, sets approval rules, performs cleanup, and applies advanced configuration options.
Configuration 'WSUS_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'UpdateServicesDsc' -ModuleVersion '1.2.1'

    Node 'WSUS_Server'
    {
        # Installs WSUS server feature
        WindowsFeature 'WSUS_UpdateServices'
        {
            Ensure = 'Present'
            Name   = 'UpdateServices'
        }

        # Installs WSUS RSAT tools with all subfeatures
        WindowsFeature 'WSUS_UpdateServicesRSAT'
        {
            Ensure              = 'Present'
            Name                = 'UpdateServices-RSAT'
            IncludeAllSubFeature = $True
        }

        # Configures WSUS server settings and synchronization with advanced options
        UpdateServicesServer 'WSUS_ServerConfig'
        {
            DependsOn                       = '[WindowsFeature]WSUS_UpdateServices'
            Ensure                          = 'Present'
            Languages                       = @('en','de','fr') # Multiple languages
            Products                        = @('Windows Server 2019','Windows 10','Office 2019')
            Classifications                 = @('*','Critical Updates','Security Updates')
            SynchronizeAutomatically        = $true
            SynchronizeAutomaticallyTimeOfDay = '15:30:00'
            ContentDirectory                = 'D:\WSUSContent' # Custom content directory
            DatabaseType                    = 'WID' # Or 'SQL'
            SqlServerName                   = 'WSUS-SQL01' # If using SQL
            SqlInstanceName                 = 'WSUSINST' # If using SQL
            UpdateSource                    = 'MicrosoftUpdate' # Or 'UpstreamWsusServer'
            UpstreamWsusServerName          = 'wsus-upstream.contoso.com'
            UpstreamWsusServerPort          = 8530
            UseSSL                          = $true
            ProxyServerName                 = 'proxy.contoso.com'
            ProxyServerPort                 = 8080
            ProxyUserName                   = 'wsusproxyuser'
            ProxyUserPassword               = 'P@ssw0rd!'
            SmtpServer                      = 'smtp.contoso.com'
            SmtpSender                      = 'wsus@contoso.com'
            SmtpRecipient                   = 'admin@contoso.com'
            SmtpSubject                     = 'WSUS Sync Notification'
            SmtpBody                        = 'WSUS synchronization completed.'
            SmtpAuthentication              = 'Basic'
            SmtpUserName                    = 'smtpuser'
            SmtpPassword                    = 'smtpP@ssw0rd!'
            ClientTargeting                 = $true
            TargetingMode                   = 'Client'
            ComputerGroups                  = @('Servers','Workstations','Test')
            ReportingRollup                 = $true
            EnableSsl                       = $true
            MaintenanceEnabled              = $true
            MaintenanceTimeOfDay            = '02:00:00'
            MaintenanceDayOfWeek            = 'Sunday'
        }

        # Approval rule for definition updates
        UpdateServicesApprovalRule 'WSUS_DefinitionUpdates'
        {
            DependsOn       = '[UpdateServicesServer]WSUS_ServerConfig'
            Name            = 'Definition Updates'
            Classifications = 'e0789628-ce08-4437-be74-2495b842f43b'
            Enabled         = $true
            RunRuleNow      = $true
            ComputerGroup   = 'Workstations'
        }

        # Approval rule for critical updates
        UpdateServicesApprovalRule 'WSUS_CriticalUpdates'
        {
            DependsOn       = '[UpdateServicesServer]WSUS_ServerConfig'
            Name            = 'Critical Updates'
            Classifications = 'e6cf1350-c01b-414d-a61f-263d14d133b4'
            Enabled         = $true
            RunRuleNow      = $true
            ComputerGroup   = 'Servers'
        }

        # Approval rule for security updates
        UpdateServicesApprovalRule 'WSUS_SecurityUpdates'
        {
            DependsOn       = '[UpdateServicesServer]WSUS_ServerConfig'
            Name            = 'Security Updates'
            Classifications = '0fa1201d-4330-4fa8-8ae9-b877473b6441'
            Enabled         = $true
            RunRuleNow      = $true
            ComputerGroup   = 'Servers'
        }

        # Approval rule for service packs
        UpdateServicesApprovalRule 'WSUS_ServicePacks'
        {
            DependsOn       = '[UpdateServicesServer]WSUS_ServerConfig'
            Name            = 'Service Packs'
            Classifications = '68c5b0a3-d1a6-4553-ae49-01d3a7827828'
            Enabled         = $true
            RunRuleNow      = $true
            ComputerGroup   = 'Workstations'
        }

        # Approval rule for update rollups
        UpdateServicesApprovalRule 'WSUS_UpdateRollUps'
        {
            DependsOn       = '[UpdateServicesServer]WSUS_ServerConfig'
            Name            = 'Update RollUps'
            Classifications = '28bc880e-0592-4cbf-8f95-c79b17911d5f'
            Enabled         = $true
            RunRuleNow      = $true
            ComputerGroup   = 'Test'
        }

        # Example: Additional computer group management (custom resource or script)
        # You may use a custom DSC resource or script to create/manage computer groups if needed

        # Example: Firewall rule for WSUS communication
        Firewall 'WSUS_HTTP'
        {
            Name    = 'WSUS-HTTP-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        # Cleanup operation for WSUS
        UpdateServicesCleanup 'WSUS_Cleanup'
        {
            DependsOn                   = '[UpdateServicesServer]WSUS_ServerConfig'
            Ensure                      = 'Present'
            DeclineExpiredUpdates       = $true
            DeclineSupersededUpdates    = $true
            CleanupObsoleteUpdates      = $true
            CleanupUnneededContentFiles = $true
        }
    }
}