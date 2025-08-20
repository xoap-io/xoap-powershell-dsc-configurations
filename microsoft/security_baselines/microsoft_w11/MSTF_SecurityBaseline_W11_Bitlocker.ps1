
Configuration 'MSTF_SecurityBaseline_W11_Bitlocker'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_Bitlocker'
     {
         # Enables enhanced PIN for BitLocker, increasing authentication strength
         RegistryPolicyFile 'UseEnhancedPin'
         {
              ValueName = 'UseEnhancedPin'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
         }

         # Allows cross-organization access to removable drives (set to 0 to allow)
         RegistryPolicyFile 'RDVDenyCrossOrg'
         {
              ValueName = 'RDVDenyCrossOrg'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
         }

         # Disables external DMA ports when device is locked to prevent DMA attacks
         RegistryPolicyFile 'DisableExternalDMAUnderLock'
         {
              ValueName = 'DisableExternalDMAUnderLock'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
         }

         # Sets power management for BitLocker to prevent sleep on battery (DC)
         RegistryPolicyFile 'DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
         }

         # Sets power management for BitLocker to prevent sleep on AC power
         RegistryPolicyFile 'ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
         }

         # Denies installation of specific device classes for security
         RegistryPolicyFile 'DenyDeviceClasses'
         {
              ValueName = 'DenyDeviceClasses'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
         }

         # Applies device class restrictions retroactively to already installed devices
         RegistryPolicyFile 'DenyDeviceClassesRetroactive'
         {
              ValueName = 'DenyDeviceClassesRetroactive'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
         }

         # Denies installation of IEEE 1394 (FireWire) devices for DMA attack mitigation
         RegistryPolicyFile 'DenyDeviceClasses'
         {
              ValueName = '1'
              ValueData = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
         }

         # Denies write access to removable drives not protected by BitLocker
         RegistryPolicyFile 'RDVDenyWriteAccess'
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
