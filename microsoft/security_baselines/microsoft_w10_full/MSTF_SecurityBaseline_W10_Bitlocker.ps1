# DSC Configuration: MSTF_SecurityBaseline_W10_Bitlocker
# Purpose: Applies BitLocker and device installation restrictions for Windows 10.
Configuration 'MSTF_SecurityBaseline_W10_Bitlocker'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W10_Bitlocker'
    {
        RegistryPolicyFile 'UseAdvancedStartup'
        {
            ValueName  = 'UseAdvancedStartup'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'UseEnhancedPin'
        {
            ValueName  = 'UseEnhancedPin'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'EnableBDEWithNoTPM'
        {
            ValueName  = 'EnableBDEWithNoTPM'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'UseTPM'
        {
            ValueName  = 'UseTPM'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'UseTPMKey'
        {
            ValueName  = 'UseTPMKey'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'UseTPMPIN'
        {
            ValueName  = 'UseTPMPIN'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'DisableExternalDMAUnderLock'
        {
            ValueName  = 'DisableExternalDMAUnderLock'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'RDVDenyWriteAccess'
        {
            ValueName  = 'RDVDenyWriteAccess'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        }

        RegistryPolicyFile 'DenyDeviceClasses'
        {
            ValueName  = 'DenyDeviceClasses'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
        }

        RegistryPolicyFile 'DenyDeviceClassesRetroactive'
        {
            ValueName  = 'DenyDeviceClassesRetroactive'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
        }

        RegistryPolicyFile 'DenyDeviceClass_IEEE1394'
        {
            ValueName  = '1'
            ValueData  = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'
        }

        RegistryPolicyFile 'DCSettingIndex'
        {
            ValueName  = 'DCSettingIndex'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
        }

        RegistryPolicyFile 'ACSettingIndex'
        {
            ValueName  = 'ACSettingIndex'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W10_Bitlocker -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W10_Bitlocker'
