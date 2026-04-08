# DSC Configuration: MSTF_SecurityBaseline_W10_Credential_Guard
# Purpose: Enables Virtualization-Based Security and Credential Guard for Windows 10.
Configuration 'MSTF_SecurityBaseline_W10_Credential_Guard'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W10_Credential_Guard'
    {
        RegistryPolicyFile 'EnableVirtualizationBasedSecurity'
        {
            ValueName  = 'EnableVirtualizationBasedSecurity'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'RequirePlatformSecurityFeatures'
        {
            ValueName  = 'RequirePlatformSecurityFeatures'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'HypervisorEnforcedCodeIntegrity'
        {
            ValueName  = 'HypervisorEnforcedCodeIntegrity'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'HVCIMATRequired'
        {
            ValueName  = 'HVCIMATRequired'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'LsaCfgFlags'
        {
            ValueName  = 'LsaCfgFlags'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'ConfigureSystemGuardLaunch'
        {
            ValueName  = 'ConfigureSystemGuardLaunch'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W10_Credential_Guard -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W10_Credential_Guard'
