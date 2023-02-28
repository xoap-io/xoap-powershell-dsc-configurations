
Configuration MSTF_SecurityBaseline_W10_22H2_Bitlocker
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

	Node MSTF_SecurityBaseline_W10_22H2_Bitlocker
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseEnhancedPin'
         {
              ValueName = 'UseEnhancedPin'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVDenyCrossOrg'
         {
              ValueName = 'RDVDenyCrossOrg'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\DisableExternalDMAUnderLock'
         {
              ValueName = 'DisableExternalDMAUnderLock'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
         {
              ValueName = 'DenyDeviceClasses'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClassesRetroactive'
         {
              ValueName = 'DenyDeviceClassesRetroactive'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\1'
         {
              ValueName = '1'
              ValueData = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE\RDVDenyWriteAccess'
         {
              ValueName = 'RDVDenyWriteAccess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
