Configuration AzureConnectedMachineAgent {
    Import-DscResource -ModuleName PSDSCResources
    Import-DscResource -Module @{ModuleName = 'AzureConnectedMachineDsc'; ModuleVersion = '1.2.0'}

    Node $AllNodes.NodeName
    {
        Package AzureHIMDService
        {
            Name        = 'Azure Connected Machine Agent'
            Ensure      = 'Present'
            ProductId   = '{B3A65ABF-11A7-4C13-9BA7-3BFAB7B79760}'
            Path        = 'https://download.microsoft.com/download/e/a/4/ea4ea4a9-a947-4c94-995c-52eaf200f651/AzureConnectedMachineAgent.msi'
        }

        Service HIMDS
        {
            Ensure  = 'Present'
            Name    = 'HIMDS'
            State   = 'Running'
        }

        AzureConnectedMachineAgentDsc Connect
        {
            TenantId        = $Node.TenantId
            SubscriptionId  = $Node.SubscriptionId
            ResourceGroup   = $Node.ResourceGroup
            Location        = $Node.Location
            Tags            = $Node.Tags
            Credential      = $Node.Credential
        }

        AzcmagentConfig Ports
        {
            IsSingleInstance = 'Yes'
            incomingconnections_ports = '22','2222'
        }
    }
}

. $PSScriptRoot\private.ConfigurationData.ps1

AzureConnectedMachineAgent -out c:\dsc -configurationdata $configurationData
