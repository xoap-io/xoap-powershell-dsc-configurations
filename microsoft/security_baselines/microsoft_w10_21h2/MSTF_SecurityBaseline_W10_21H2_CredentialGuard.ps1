﻿
Configuration MSTF_SecurityBaseline_W10_21H2_CredentialGuard
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node MSTF_SecurityBaseline_W10_21H2_CredentialGuard
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
         {
              ValueName = 'EnableVirtualizationBasedSecurity'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
         {
              ValueName = 'RequirePlatformSecurityFeatures'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
         {
              ValueName = 'HypervisorEnforcedCodeIntegrity'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
         {
              ValueName = 'HVCIMATRequired'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
         {
              ValueName = 'LsaCfgFlags'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
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
