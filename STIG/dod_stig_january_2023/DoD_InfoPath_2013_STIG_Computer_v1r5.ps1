
Configuration 'DoD_InfoPath_2013_STIG_Computer_v1r5'
{
	Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_InfoPath_2013_STIG_Computer_v1r5'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\infopath\security\aptca_allowlist'
         {
              ValueName = 'aptca_allowlist'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\infopath\security'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
