
Configuration 'MSTF_SecurityBaseline_W10_1607_Credential_Guard'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'MSTF_SecurityBaseline_W10_1607_Credential_Guard'
	{
          # Enable Virtualization Based Security
          RegistryPolicyFile 'EnableVirtualizationBasedSecurity'
          {
               ValueName = 'EnableVirtualizationBasedSecurity'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          }

          # Require Platform Security Features
          RegistryPolicyFile 'RequirePlatformSecurityFeatures'
          {
               ValueName = 'RequirePlatformSecurityFeatures'
               ValueData = 3
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          }

          # Enable Hypervisor Enforced Code Integrity
          RegistryPolicyFile 'HypervisorEnforcedCodeIntegrity'
          {
               ValueName = 'HypervisorEnforcedCodeIntegrity'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          }

          # Configure LSA Configuration Flags
          RegistryPolicyFile 'LsaCfgFlags'
          {
               ValueName = 'LsaCfgFlags'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          }

          # Refresh registry policy to apply changes
          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
               IsSingleInstance = 'Yes'
          }
     }
}
