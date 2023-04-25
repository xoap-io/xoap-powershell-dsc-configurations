
Configuration DoD_Skype_for_Business_2016_STIG_Computer_v1r1
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node DoD_Skype_for_Business_2016_STIG_Computer_v1r1
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
         {
              ValueName = 'savepassword'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
         {
              ValueName = 'enablesiphighsecuritymode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
         {
              ValueName = 'disablehttpconnect'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
