
Configuration 'DoD_Windows_Firewall_STIG_Computer_v1r7'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_Windows_Firewall_STIG_Computer_v1r7'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
         {
              ValueName = 'PolicyVersion'
              ValueData = 539
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
         {
              ValueName = 'LogFileSize'
              ValueData = 16384
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
         {
              ValueName = 'LogDroppedPackets'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
         {
              ValueName = 'LogSuccessfulConnections'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
         {
              ValueName = 'LogFileSize'
              ValueData = 16384
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
         {
              ValueName = 'LogDroppedPackets'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
         {
              ValueName = 'LogSuccessfulConnections'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
         {
              ValueName = 'AllowLocalPolicyMerge'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
         {
              ValueName = 'AllowLocalIPsecPolicyMerge'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
         {
              ValueName = 'LogFileSize'
              ValueData = 16384
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
         {
              ValueName = 'LogDroppedPackets'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
         {
              ValueName = 'LogSuccessfulConnections'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
