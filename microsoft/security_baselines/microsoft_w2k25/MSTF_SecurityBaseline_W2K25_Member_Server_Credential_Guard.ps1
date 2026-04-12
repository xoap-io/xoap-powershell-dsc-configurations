# DSC Configuration: MSTF_SecurityBaseline_W2K25_Member_Server_Credential_Guard
# Purpose: Applies Virtualization-Based Security and Credential Guard policies for Windows Server 2025 member servers.
Configuration 'MSTF_SecurityBaseline_W2K25_Member_Server_Credential_Guard'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W2K25_Member_Server_Credential_Guard'
    {
        # --- Virtualization-Based Security ---
        RegistryPolicyFile 'VBS_Enable'
        {
            ValueName  = 'EnableVirtualizationBasedSecurity'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'VBS_PlatformSecurity'
        {
            ValueName  = 'RequirePlatformSecurityFeatures'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'VBS_HVCI'
        {
            ValueName  = 'HypervisorEnforcedCodeIntegrity'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        RegistryPolicyFile 'VBS_HVCIMATRequired'
        {
            ValueName  = 'HVCIMATRequired'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # --- Credential Guard ---
        RegistryPolicyFile 'CredentialGuard_LsaCfgFlags'
        {
            ValueName  = 'LsaCfgFlags'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # --- System Guard ---
        RegistryPolicyFile 'SystemGuard_Enable'
        {
            ValueName  = 'SystemGuardEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # --- W2K25-specific: Kernel Shadow Stacks ---
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
MSTF_SecurityBaseline_W2K25_Member_Server_Credential_Guard -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W2K25_Member_Server_Credential_Guard'
