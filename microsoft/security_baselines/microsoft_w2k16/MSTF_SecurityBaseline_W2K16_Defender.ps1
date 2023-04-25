
Configuration MSTF_SecurityBaseline_W10_1607_Defender
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node MSTF_SecurityBaseline_W10_1607_Defender
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware'
         {
              ValueName = 'DisableAntiSpyware'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring'
         {
              ValueName = 'DisableBehaviorMonitoring'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
         {
              ValueName = 'DisableRemovableDriveScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
         {
              ValueName = 'DisableEmailScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\LocalSettingOverrideSpynetReporting'
         {
              ValueName = 'LocalSettingOverrideSpynetReporting'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
         {
              ValueName = 'SubmitSamplesConsent'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
         {
              ValueName = 'SpynetReporting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
