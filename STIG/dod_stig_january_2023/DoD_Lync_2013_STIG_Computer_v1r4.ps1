
Configuration 'DoD_Lync_2013_STIG_Computer_v1r4'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_Lync_2013_STIG_Computer_v1r4'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\savepassword'
         {
              ValueName = 'savepassword'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\lync'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\enablesiphighsecuritymode'
         {
              ValueName = 'enablesiphighsecuritymode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\lync'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\disablehttpconnect'
         {
              ValueName = 'disablehttpconnect'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\lync'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}