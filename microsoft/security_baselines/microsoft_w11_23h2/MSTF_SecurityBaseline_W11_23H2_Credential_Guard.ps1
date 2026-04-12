# DSC Configuration: MSTF_SecurityBaseline_W11_23H2_Credential_Guard
# Purpose: Enables Virtualization-Based Security and Credential Guard for Windows 11 23H2.
Configuration 'MSTF_SecurityBaseline_W11_23H2_Credential_Guard'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W11_23H2_Credential_Guard'
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

        RegistryPolicyFile 'CredentialGuard_MachineType'
        {
            ValueName  = 'MachineType'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'KernelShadowStacks'
        {
            ValueName  = 'KernelShadowStacksEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W11_23H2_Credential_Guard -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W11_23H2_Credential_Guard'
