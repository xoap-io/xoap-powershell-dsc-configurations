

# DSC Configuration: MSTF_SecurityBaseline_W11_22H2_Credential_Guard
# Purpose: Applies Credential Guard and virtualization-based security baseline settings for Windows 11 22H2.
Configuration 'MSTF_SecurityBaseline_W11_22H2_Credential_Guard'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

    Node 'MSTF_SecurityBaseline_W11_22H2_Credential_Guard'
    {
        # Enables virtualization-based security
        RegistryPolicyFile 'EnableVirtualizationBasedSecurity'
        {
            ValueName     = 'EnableVirtualizationBasedSecurity'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Requires platform security features
        RegistryPolicyFile 'RequirePlatformSecurityFeatures'
        {
            ValueName     = 'RequirePlatformSecurityFeatures'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Enables hypervisor enforced code integrity
        RegistryPolicyFile 'HypervisorEnforcedCodeIntegrity'
        {
            ValueName     = 'HypervisorEnforcedCodeIntegrity'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Requires HVCI MAT
        RegistryPolicyFile 'HVCIMATRequired'
        {
            ValueName     = 'HVCIMATRequired'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Enables LSA protection
        RegistryPolicyFile 'LsaCfgFlags'
        {
            ValueName     = 'LsaCfgFlags'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Configures System Guard launch
        RegistryPolicyFile 'ConfigureSystemGuardLaunch'
        {
            ValueName     = 'ConfigureSystemGuardLaunch'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Configures Kernel Shadow Stacks launch
        RegistryPolicyFile 'ConfigureKernelShadowStacksLaunch'
        {
            ValueName     = 'ConfigureKernelShadowStacksLaunch'
            ValueData     = 1
            ValueType     = 'Dword'
            TargetType    = 'ComputerConfiguration'
            Key           = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # Refreshes registry policy to activate client-side extension
        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
