
Configuration MSTF_SecurityBaseline_M365_Apps_v2206_Legacy_JScript_Block_Computer
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node MSTF_SecurityBaseline_M365_Apps_v2206_Legacy_JScript_Block_Computer
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 69632
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
