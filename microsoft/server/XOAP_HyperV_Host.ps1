# DSC Configuration: XOAP_HyperV_Host
# Purpose: Configures a Windows Server Hyper-V host with default VM paths and virtual switch.
Configuration 'XOAP_HyperV_Host'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xHyper-V'              -ModuleVersion '3.17.0.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_HyperV_Host'
    {
        # --- Windows Features ---
        WindowsFeature 'HyperV'
        {
            Name                 = 'Hyper-V'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'HyperV_Tools'
        {
            Name      = 'Hyper-V-Tools'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]HyperV'
        }

        WindowsFeature 'HyperV_PowerShell'
        {
            Name      = 'Hyper-V-PowerShell'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]HyperV'
        }

        WindowsFeature 'RSAT_HyperV'
        {
            Name      = 'RSAT-Hyper-V-Tools'
            Ensure    = 'Present'
        }

        # --- Services ---
        Service 'VMMS'
        {
            Name        = 'vmms'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[WindowsFeature]HyperV'
        }

        Service 'VmAppHealthService'
        {
            Name        = 'VmAppHealthService'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[WindowsFeature]HyperV'
        }

        # --- VM default paths ---
        File 'VMStoragePath'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Hyper-V\Virtual Machines'
        }

        File 'VHDStoragePath'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Hyper-V\Virtual Hard Disks'
        }

        # --- External virtual switch (requires physical NIC named 'Ethernet') ---
        xVMSwitch 'ExternalSwitch'
        {
            Name              = 'External'
            Type              = 'External'
            NetAdapterName    = 'Ethernet'
            Ensure            = 'Present'
            AllowManagementOS = $true
            DependsOn         = '[WindowsFeature]HyperV'
        }

        # --- Security: Enable SLAT check ---
        Registry 'HyperV_RequireSLAT'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
            Ensure    = 'Present'
            ValueName = 'MinVmVersion'
            ValueType = 'String'
            ValueData = '9.0'
        }

        # --- Live Migration: disabled by default for standalone host ---
        Registry 'HyperV_DisableLiveMigration'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\Replication'
            Ensure    = 'Present'
            ValueName = 'DisableLiveMigration'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_HyperV_Host -OutputPath 'C:\DSC\XOAP_HyperV_Host'
