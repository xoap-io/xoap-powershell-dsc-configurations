Configuration 'DoD_Windows_Firewall_STIG_Computer_v2r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'DoD_Windows_Firewall_STIG_Computer_v2r1'
    {
        # WF-00-000001: Domain profile must be enabled
        RegistryPolicyFile 'WF_Domain_EnableFirewall'
        {
            ValueName  = 'EnableFirewall'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
        }

        RegistryPolicyFile 'WF_Domain_DefaultInboundAction'
        {
            ValueName  = 'DefaultInboundAction'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
        }

        RegistryPolicyFile 'WF_Domain_DisableNotifications'
        {
            ValueName  = 'DisableNotifications'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
        }

        RegistryPolicyFile 'WF_Domain_LogDroppedPackets'
        {
            ValueName  = 'LogDroppedPackets'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        }

        RegistryPolicyFile 'WF_Domain_LogSuccessfulConnections'
        {
            ValueName  = 'LogSuccessfulConnections'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        }

        RegistryPolicyFile 'WF_Domain_LogFileSize'
        {
            ValueName  = 'LogFileSize'
            ValueData  = 16384
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
        }

        # WF Private profile
        RegistryPolicyFile 'WF_Private_EnableFirewall'
        {
            ValueName  = 'EnableFirewall'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        }

        RegistryPolicyFile 'WF_Private_DefaultInboundAction'
        {
            ValueName  = 'DefaultInboundAction'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
        }

        RegistryPolicyFile 'WF_Private_LogDroppedPackets'
        {
            ValueName  = 'LogDroppedPackets'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
        }

        RegistryPolicyFile 'WF_Private_LogFileSize'
        {
            ValueName  = 'LogFileSize'
            ValueData  = 16384
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
        }

        # WF Public profile
        RegistryPolicyFile 'WF_Public_EnableFirewall'
        {
            ValueName  = 'EnableFirewall'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
        }

        RegistryPolicyFile 'WF_Public_DefaultInboundAction'
        {
            ValueName  = 'DefaultInboundAction'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
        }

        RegistryPolicyFile 'WF_Public_DisableNotifications'
        {
            ValueName  = 'DisableNotifications'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
        }

        RegistryPolicyFile 'WF_Public_LogDroppedPackets'
        {
            ValueName  = 'LogDroppedPackets'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        }

        RegistryPolicyFile 'WF_Public_LogFileSize'
        {
            ValueName  = 'LogFileSize'
            ValueData  = 16384
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_Windows_Firewall_STIG_Computer_v2r1 -OutputPath 'C:\DSC\DoD_Windows_Firewall_STIG_Computer_v2r1'
