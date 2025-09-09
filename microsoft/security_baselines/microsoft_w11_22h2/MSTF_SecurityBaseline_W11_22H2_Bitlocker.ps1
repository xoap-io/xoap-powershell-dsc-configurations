

# DSC Configuration: MSTF_SecurityBaseline_W11_22H2_Bitlocker
# Purpose: Applies Bitlocker and device install security baseline settings for Windows 11 22H2.
Configuration 'MSTF_SecurityBaseline_W11_22H2_Bitlocker'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

    Node 'MSTF_SecurityBaseline_W11_22H2_Bitlocker'
    {
        # Enables enhanced PIN for Bitlocker
        RegistryPolicyFile 'UseEnhancedPin'
        {
            ValueName     = 'UseEnhancedPin'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        # Allows cross-organization DVD access
        RegistryPolicyFile 'RDVDenyCrossOrg'
        {
            ValueName     = 'RDVDenyCrossOrg'
            ValueData     = 0
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        # Disables external DMA under lock
        RegistryPolicyFile 'DisableExternalDMAUnderLock'
        {
            ValueName     = 'DisableExternalDMAUnderLock'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        # Sets DC power setting index
        RegistryPolicyFile 'DCSettingIndex'
        {
            ValueName     = 'DCSettingIndex'
            ValueData     = 0
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
        }

        # Sets AC power setting index
        RegistryPolicyFile 'ACSettingIndex'
        {
            ValueName     = 'ACSettingIndex'
            ValueData     = 0
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
        }

        # Denies device classes installation
        RegistryPolicyFile 'DenyDeviceClasses'
        {
            ValueName     = 'DenyDeviceClasses'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
        }

        # Denies device classes retroactively
        RegistryPolicyFile 'DenyDeviceClassesRetroactive'
        {
            ValueName     = 'DenyDeviceClassesRetroactive'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
        }

        # Denies installation of specific device class (IEEE 1394)
        RegistryPolicyFile 'DenyDeviceClass_1'
        {
            ValueName     = '1'
            ValueData     = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
            ValueType     = 'String'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
        }

        # Denies write access to DVD for Bitlocker
        RegistryPolicyFile 'RDVDenyWriteAccess'
        {
            ValueName     = 'RDVDenyWriteAccess'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE'
        }

        # Refreshes registry policy to activate client-side extension
        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
