# DSC Configuration: MSTF_SecurityBaseline_W11_22H2_Computer
# Purpose: Applies Microsoft Security Baseline computer policies for Windows 11 22H2.
Configuration 'MSTF_SecurityBaseline_W11_22H2_Computer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'       -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'    -ModuleVersion '2.10.0.0'

    Node 'MSTF_SecurityBaseline_W11_22H2_Computer'
    {
        # --- Account Policies ---
        AccountPolicy 'AccountPolicies'
        {
            Name                                        = 'AccountPolicies'
            Enforce_password_history                    = 24
            Maximum_Password_Age                        = 60
            Minimum_Password_Age                        = 1
            Minimum_Password_Length                     = 14
            Password_must_meet_complexity_requirements  = 'Enabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            Account_lockout_duration                    = 15
            Account_lockout_threshold                   = 10
            Reset_account_lockout_counter_after         = 15
        }

        # --- UAC ---
        RegistryPolicyFile 'UAC_AdminApprovalMode'
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
        RegistryPolicyFile 'SMBClient_RequireSigning'
        {
            ValueName  = 'RequireSecuritySignature'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        }

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

        # --- LSA ---
        RegistryPolicyFile 'LSA_RunAsPPL'
        {
            ValueName  = 'RunAsPPL'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'LSA_RestrictAnonymous'
        {
            ValueName  = 'RestrictAnonymous'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # --- RDP ---
        RegistryPolicyFile 'RDP_NLA_Required'
        {
            ValueName  = 'UserAuthentication'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        }

        RegistryPolicyFile 'RDP_EncryptionLevel'
        {
            ValueName  = 'MinEncryptionLevel'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        }

        # --- AutoPlay ---
        RegistryPolicyFile 'DisableAutoPlay'
        {
            ValueName  = 'NoDriveTypeAutoRun'
            ValueData  = 255
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

        # --- Screen Saver (HKCU -> UserConfiguration) ---
        RegistryPolicyFile 'ScreenSaver_Enabled'
        {
            ValueName  = 'ScreenSaveActive'
            ValueData  = '1'
            ValueType  = 'String'
            TargetType = 'UserConfiguration'
            Key        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
        }

        RegistryPolicyFile 'ScreenSaver_PasswordProtected'
        {
            ValueName  = 'ScreenSaverIsSecure'
            ValueData  = '1'
            ValueType  = 'String'
            TargetType = 'UserConfiguration'
            Key        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
        }

        RegistryPolicyFile 'ScreenSaver_Timeout'
        {
            ValueName  = 'ScreenSaveTimeOut'
            ValueData  = '900'
            ValueType  = 'String'
            TargetType = 'UserConfiguration'
            Key        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
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

        AuditPolicySubcategory 'Audit_PolicyChange_Success'
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_AccountManagement_User_Success'
        {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit_AccountManagement_User_Failure'
        {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W11_22H2_Computer -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W11_22H2_Computer'
