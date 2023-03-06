
Configuration DoD_OneDrive_for_Business_2016_STIG_Computer_v2r2
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

	Node DoD_OneDrive_for_Business_2016_STIG_Computer_v2r2
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
