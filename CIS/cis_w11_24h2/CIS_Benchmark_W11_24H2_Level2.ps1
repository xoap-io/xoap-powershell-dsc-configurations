# DSC Configuration: CIS_Benchmark_W11_24H2_Level2
# Purpose: Applies CIS Benchmark Level 2 — stricter controls for high-security environments — for Windows 11 24H2.
Configuration 'CIS_Benchmark_W11_24H2_Level2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'       -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'    -ModuleVersion '2.10.0.0'

    Node 'CIS_Benchmark_W11_24H2_Level2'
    {
        # --- Account Policies (CIS Level 1) ---
        AccountPolicy 'AccountPolicies'
        {
            Name                                        = 'AccountPolicies'
            Enforce_password_history                    = 24
            Maximum_Password_Age                        = 365
            Minimum_Password_Age                        = 1
            Minimum_Password_Length                     = 14
            Password_must_meet_complexity_requirements  = 'Enabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            Account_lockout_duration                    = 15
            Account_lockout_threshold                   = 5
            Reset_account_lockout_counter_after         = 15
        }

        # --- Interactive Logon ---
        RegistryPolicyFile 'Logon_DontDisplayLastUser'
        {
            ValueName  = 'DontDisplayLastUserName'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        RegistryPolicyFile 'Logon_MachineInactivityLimit'
        {
            ValueName  = 'InactivityTimeoutSecs'
            ValueData  = 900
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        # --- Network Access ---
        RegistryPolicyFile 'Network_RestrictAnonymousSAM'
        {
            ValueName  = 'RestrictAnonymousSAM'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'Network_RestrictAnonymous'
        {
            ValueName  = 'RestrictAnonymous'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'Network_NoLMHash'
        {
            ValueName  = 'NoLMHash'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # --- Network Security: LAN Manager ---
        RegistryPolicyFile 'Network_LmCompatibilityLevel'
        {
            ValueName  = 'LmCompatibilityLevel'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'Network_NTLMMinClientSec'
        {
            ValueName  = 'NTLMMinClientSec'
            ValueData  = 537395200
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        }

        # --- UAC ---
        RegistryPolicyFile 'UAC_EnableLUA'
        {
            ValueName  = 'EnableLUA'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        RegistryPolicyFile 'UAC_ConsentPromptAdmin'
        {
            ValueName  = 'ConsentPromptBehaviorAdmin'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        RegistryPolicyFile 'UAC_PromptOnSecureDesktop'
        {
            ValueName  = 'PromptOnSecureDesktop'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        # --- SMB Signing ---
        RegistryPolicyFile 'SMB_ClientRequireSigning'
        {
            ValueName  = 'RequireSecuritySignature'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        }

        RegistryPolicyFile 'SMB_ServerRequireSigning'
        {
            ValueName  = 'RequireSecuritySignature'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        }

        # --- Audit Policies ---
        AuditPolicySubcategory 'Audit_CredentialValidation_Success'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_CredentialValidation_Failure'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_Logon_Success'
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_Logon_Failure'
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_AccountLockout_Failure'
        {
            Name      = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_PolicyChange_Success'
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_SensitivePrivilege_Success'
        {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_SensitivePrivilege_Failure'
        {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_ProcessCreation_Success'
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_SystemIntegrity_Success'
        {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_SystemIntegrity_Failure'
        {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # --- Level 2: Disable Auto-Admin Logon ---
        RegistryPolicyFile 'L2_DisableAutoAdminLogon'
        {
            ValueName  = 'AutoAdminLogon'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        }

        # --- Level 2: Disable WDigest Authentication ---
        RegistryPolicyFile 'L2_DisableWDigest'
        {
            ValueName  = 'UseLogonCredential'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
        }

        # --- Level 2: Disable LLMNR ---
        RegistryPolicyFile 'L2_DisableLLMNR'
        {
            ValueName  = 'EnableMulticast'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        }

        # --- Level 2: Disable NetBIOS over TCP/IP (registry) ---
        RegistryPolicyFile 'L2_MSS_DisableIPSourceRouting'
        {
            ValueName  = 'DisableIPSourceRouting'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        }

        # --- Level 2: Additional Audit ---
        AuditPolicySubcategory 'Audit_SpecialLogon_Success'
        {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_Logoff_Success'
        {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_OtherLogonLogoff_Success'
        {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_OtherLogonLogoff_Failure'
        {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_KernelObject_Success'
        {
            Name      = 'Kernel Object'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_RemovableStorage_Success'
        {
            Name      = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_RemovableStorage_Failure'
        {
            Name      = 'Removable Storage'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
CIS_Benchmark_W11_24H2_Level2 -OutputPath 'C:\DSC\CIS_Benchmark_W11_24H2_Level2'
