
Configuration 'MSTF_SecurityBaseline_W11_Credential_Guard'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_Credential_Guard'
     {
         # Enables Virtualization-Based Security (VBS) for Credential Guard
         RegistryPolicyFile 'EnableVirtualizationBasedSecurity'
         {
              ValueName = 'EnableVirtualizationBasedSecurity'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         # Requires platform security features (such as TPM, Secure Boot)
         RegistryPolicyFile 'RequirePlatformSecurityFeatures'
         {
              ValueName = 'RequirePlatformSecurityFeatures'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         # Enables Hypervisor Enforced Code Integrity (HVCI)
         RegistryPolicyFile 'HypervisorEnforcedCodeIntegrity'
         {
              ValueName = 'HypervisorEnforcedCodeIntegrity'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         # Requires HVCI memory access protection
         RegistryPolicyFile 'HVCIMATRequired'
         {
              ValueName = 'HVCIMATRequired'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         # Enables Credential Guard (LSA protection)
         RegistryPolicyFile 'LsaCfgFlags'
         {
              ValueName = 'LsaCfgFlags'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         # Enables System Guard Secure Launch
         RegistryPolicyFile 'ConfigureSystemGuardLaunch'
         {
              ValueName = 'ConfigureSystemGuardLaunch'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
    }
}
