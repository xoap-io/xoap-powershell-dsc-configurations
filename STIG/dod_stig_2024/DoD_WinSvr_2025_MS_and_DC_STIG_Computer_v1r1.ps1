Configuration 'DoD_WinSvr_2025_MS_and_DC_STIG_Computer_v1r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'       -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'    -ModuleVersion '2.10.0.0'

    Node 'DoD_WinSvr_2025_MS_and_DC_STIG_Computer_v1r1'
    {
        # WN25-00-000010: Require domain-joined systems to sign/seal
        RegistryPolicyFile 'WN25_00_000010'
        {
            ValueName  = 'RequireSignOrSeal'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        AccountPolicy 'WN25_PasswordPolicy'
        {
            Name                                        = 'WN25_PasswordPolicy'
            Enforce_password_history                    = 24
            Maximum_Password_Age                        = 60
            Minimum_Password_Age                        = 1
            Minimum_Password_Length                     = 14
            Password_must_meet_complexity_requirements  = 'Enabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            Account_lockout_duration                    = 15
            Account_lockout_threshold                   = 3
            Reset_account_lockout_counter_after         = 15
        }

        AuditPolicySubcategory 'WN25_AU_CredVal_Success'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_CredVal_Failure'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_Logon_Success'
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_Logon_Failure'
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_Logoff_Success'
        {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_ProcessCreation'
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_PolicyChange_Success'
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_AccountMgmt_Success'
        {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN25_AU_AccountMgmt_Failure'
        {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        RegistryPolicyFile 'WN25_AutoPlay_Disabled'
        {
            ValueName  = 'NoDriveTypeAutoRun'
            ValueData  = 255
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

        RegistryPolicyFile 'WN25_Telemetry'
        {
            ValueName  = 'AllowTelemetry'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        }

        RegistryPolicyFile 'WN25_NTLMv2'
        {
            ValueName  = 'LmCompatibilityLevel'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'WN25_RestrictAnonymousSAM'
        {
            ValueName  = 'RestrictAnonymousSAM'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'WN25_LDAPClientSigning'
        {
            ValueName  = 'LDAPClientIntegrity'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
        }

        RegistryPolicyFile 'WN25_SMBSigning'
        {
            ValueName  = 'RequireSecuritySignature'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        }

        RegistryPolicyFile 'WN25_WinRM_NoBasic'
        {
            ValueName  = 'AllowBasic'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        }

        RegistryPolicyFile 'WN25_RDP_NLA'
        {
            ValueName  = 'UserAuthentication'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        }

        UserRightsAssignment 'WN25_DenyGuestNetwork'
        {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = @('Guests')
        }

        UserRightsAssignment 'WN25_DenyGuestLocal'
        {
            Policy   = 'Deny_log_on_locally'
            Identity = @('Guests')
        }

        # WN25-00-000001 (new): LSA PPL must be set to 2 (UEFI locked) on WS2025
        RegistryPolicyFile 'WN25_LSA_RunAsPPL_2'
        {
            ValueName  = 'RunAsPPL'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # WN25-00-000002 (new): Kernel-mode Hardware-Enforced Stack Protection
        RegistryPolicyFile 'WN25_KernelShadowStacks'
        {
            ValueName  = 'KernelShadowStacksEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        }

        # WN25-00-000003 (new): Credential Guard must be enforced
        RegistryPolicyFile 'WN25_CredentialGuard'
        {
            ValueName  = 'LsaCfgFlags'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
        }

        # WN25-00-000004 (new): SMB over QUIC server-to-server auth
        RegistryPolicyFile 'WN25_SMBQUICAuth'
        {
            ValueName  = 'RequireClientAuthentication'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_WinSvr_2025_MS_and_DC_STIG_Computer_v1r1 -OutputPath 'C:\DSC\DoD_WinSvr_2025_MS_and_DC_STIG_Computer_v1r1'
