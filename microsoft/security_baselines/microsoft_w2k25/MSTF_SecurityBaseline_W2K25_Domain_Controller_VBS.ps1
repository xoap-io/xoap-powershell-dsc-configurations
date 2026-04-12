# DSC Configuration: MSTF_SecurityBaseline_W2K25_Domain_Controller_VBS
# Purpose: Applies Virtualization-Based Security policies for Windows Server 2025 Domain Controllers.
Configuration 'MSTF_SecurityBaseline_W2K25_Domain_Controller_VBS'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W2K25_Domain_Controller_VBS'
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
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # --- Credential Guard (DC mode) ---
        RegistryPolicyFile 'CredentialGuard_LsaCfgFlags'
        {
            ValueName  = 'LsaCfgFlags'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # --- LDAP Server Integrity ---
        RegistryPolicyFile 'LDAP_ServerIntegrity'
        {
            ValueName  = 'LDAPServerIntegrity'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W2K25_Domain_Controller_VBS -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W2K25_Domain_Controller_VBS'
