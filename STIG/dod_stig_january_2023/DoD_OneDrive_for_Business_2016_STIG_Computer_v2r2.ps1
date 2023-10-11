
Configuration 'DoD_OneDrive_for_Business_2016_STIG_Computer_v2r2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_OneDrive_for_Business_2016_STIG_Computer_v2r2'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
         {
              ValueName = '1111-2222-3333-4444'
              ValueData = '1111-2222-3333-4444'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
