Configuration WSUS_Server
{
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
Import-DscResource -ModuleName 'UpdateServicesDsc' -ModuleVersion '1.2.1'

    Node WSUS_Server
    {

        WindowsFeature 'UpdateServices'
        {
            Ensure = 'Present'
            Name = 'UpdateServices'
        }

        WindowsFeature 'UpdateServicesRSAT'
        {
            Ensure = 'Present'
            Name = 'UpdateServices-RSAT'
            IncludeAllSubFeature =  $True
        }

        UpdateServicesServer 'UpdateServices'
        {
            DependsOn = @(
                '[WindowsFeature]UpdateServices'
            )
            Ensure = 'Present'
            Languages = 'en'
            Products = @(
                'Windows Server 2019'
            )
            Classifications = @(
                '*'
            )
            SynchronizeAutomatically = $true
            SynchronizeAutomaticallyTimeOfDay = '15:30:00'
        }

        UpdateServicesApprovalRule 'DefinitionUpdates'
        {
            DependsOn = '[UpdateServicesServer]UpdateServices'
            Name = 'Definition Updates'
            Classifications = 'e0789628-ce08-4437-be74-2495b842f43b'
            Enabled = $true
            RunRuleNow = $true
        }

        UpdateServicesApprovalRule 'CriticalUpdates'
        {
            DependsOn = '[UpdateServicesServer]UpdateServices'
            Name = 'Critical Updates'
            Classifications = 'e6cf1350-c01b-414d-a61f-263d14d133b4'
            Enabled = $true
            RunRuleNow = $true
        }
        
        UpdateServicesApprovalRule 'SecurityUpdates'
        {
            DependsOn = '[UpdateServicesServer]UpdateServices'
            Name = 'Security Updates'
            Classifications = '0fa1201d-4330-4fa8-8ae9-b877473b6441'
            Enabled = $true
            RunRuleNow = $true
        }
        
        UpdateServicesApprovalRule 'ServicePacks'
        {
            DependsOn = '[UpdateServicesServer]UpdateServices'
            Name = 'Service Packs'
            Classifications = '68c5b0a3-d1a6-4553-ae49-01d3a7827828'
            Enabled = $true
            RunRuleNow = $true
        }

        UpdateServicesApprovalRule 'UpdateRollUps'
        {
            DependsOn = '[UpdateServicesServer]UpdateServices'
            Name = 'Update RollUps'
            Classifications = '28bc880e-0592-4cbf-8f95-c79b17911d5f'
            Enabled = $true
            RunRuleNow = $true
        }

        UpdateServicesCleanup 'UpdateServices'
        {
            DependsOn = '[UpdateServicesServer]UpdateServices'
            Ensure = 'Present'
            DeclineExpiredUpdates = $true
            DeclineSupersededUpdates = $true
            CleanupObsoleteUpdates = $true
            CleanupUnneededContentFiles = $true
        } 
    }
}
WSUS_Server