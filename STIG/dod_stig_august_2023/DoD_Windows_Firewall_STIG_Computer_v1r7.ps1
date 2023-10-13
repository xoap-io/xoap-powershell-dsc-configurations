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
              TargetType = 'ComputerConfiguration'
              ValueData = 539
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall'
              ValueType = 'Dword'
              ValueName = 'PolicyVersion'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueType = 'Dword'
              ValueName = 'EnableFirewall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueType = 'Dword'
              ValueName = 'DefaultOutboundAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
              ValueType = 'Dword'
              ValueName = 'DefaultInboundAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16384
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogFileSize'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogDroppedPackets'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogSuccessfulConnections'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueType = 'Dword'
              ValueName = 'EnableFirewall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueType = 'Dword'
              ValueName = 'DefaultOutboundAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
              ValueType = 'Dword'
              ValueName = 'DefaultInboundAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16384
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogFileSize'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogDroppedPackets'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogSuccessfulConnections'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueType = 'Dword'
              ValueName = 'EnableFirewall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueType = 'Dword'
              ValueName = 'DefaultOutboundAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueType = 'Dword'
              ValueName = 'DefaultInboundAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueType = 'Dword'
              ValueName = 'AllowLocalPolicyMerge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
              ValueType = 'Dword'
              ValueName = 'AllowLocalIPsecPolicyMerge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16384
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogFileSize'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogDroppedPackets'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
              ValueType = 'Dword'
              ValueName = 'LogSuccessfulConnections'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
