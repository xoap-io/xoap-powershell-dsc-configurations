# DSC Configuration: MSTF_SecurityBaseline_W2K25_Member_Server
# Purpose: Applies Microsoft Security Baseline member server policies for Windows Server 2025.
Configuration 'MSTF_SecurityBaseline_W2K25_Member_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W2K25_Member_Server'
    {
        # --- Netlogon Signing ---
        RegistryPolicyFile 'Netlogon_RequireSignOrSeal'
        {
            ValueName  = 'RequireSignOrSeal'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        RegistryPolicyFile 'Netlogon_SealSecureChannel'
        {
            ValueName  = 'SealSecureChannel'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        RegistryPolicyFile 'Netlogon_SignSecureChannel'
        {
            ValueName  = 'SignSecureChannel'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        RegistryPolicyFile 'Netlogon_RequireStrongKey'
        {
            ValueName  = 'RequireStrongKey'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        # --- LSA ---
        RegistryPolicyFile 'LSA_RestrictAnonymousSAM'
        {
            ValueName  = 'RestrictAnonymousSAM'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # --- LDAP Client ---
        RegistryPolicyFile 'LDAP_ClientIntegrity'
        {
            ValueName  = 'LDAPClientIntegrity'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap'
        }

        # --- SMB ---
        RegistryPolicyFile 'SMBServer_RequireSigning'
        {
            ValueName  = 'RequireSecuritySignature'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        }

        # --- WinRM ---
        RegistryPolicyFile 'WinRM_DisableBasicAuth'
        {
            ValueName  = 'AllowBasic'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
        }

        RegistryPolicyFile 'WinRM_DisableUnencrypted'
        {
            ValueName  = 'AllowUnencryptedTraffic'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
        }

        # --- NTLM ---
        RegistryPolicyFile 'NTLM_MinClientSec'
        {
            ValueName  = 'NTLMMinClientSec'
            ValueData  = 537395200
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        }

        RegistryPolicyFile 'NTLM_LmCompatibilityLevel'
        {
            ValueName  = 'LmCompatibilityLevel'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W2K25_Member_Server -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W2K25_Member_Server'
