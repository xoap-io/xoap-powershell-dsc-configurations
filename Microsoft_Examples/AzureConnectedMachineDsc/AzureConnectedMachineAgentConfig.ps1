Configuration AzureConnectedMachineAgentConfig {
    Import-DscResource -Module @{ModuleName = 'AzureConnectedMachineDsc'; ModuleVersion = '1.2.0' }

    AzcmagentConfig Ports
    {
        IsSingleInstance            = 'Yes'
        incomingconnections_ports   = '22'
    }
}

AzureConnectedMachineAgentConfig
