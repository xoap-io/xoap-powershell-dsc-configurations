Configuration 'DoD_WinSvr_2022_MS_and_DC_STIG_Computer_v2r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'       -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'    -ModuleVersion '2.10.0.0'

    Node 'DoD_WinSvr_2022_MS_and_DC_STIG_Computer_v2r1'
    {
        # WN22-00-000010: Require domain-joined systems to sign/seal
        RegistryPolicyFile 'WN22_00_000010'
        {
            ValueName  = 'RequireSignOrSeal'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        AccountPolicy 'WN22_PasswordPolicy'
        {
            Name                                        = 'WN22_PasswordPolicy'
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

        AuditPolicySubcategory 'WN22_AU_CredVal_Success'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_CredVal_Failure'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_Logon_Success'
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_Logon_Failure'
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_Logoff_Success'
        {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_ProcessCreation'
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_PolicyChange_Success'
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_AccountMgmt_Success'
        {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN22_AU_AccountMgmt_Failure'
        {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        RegistryPolicyFile 'WN22_AutoPlay_Disabled'
        {
            ValueName  = 'NoDriveTypeAutoRun'
            ValueData  = 255
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

        RegistryPolicyFile 'WN22_Telemetry'
        {
            ValueName  = 'AllowTelemetry'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        }

        RegistryPolicyFile 'WN22_NTLMv2'
        {
            ValueName  = 'LmCompatibilityLevel'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'WN22_LSA_RunAsPPL'
        {
            ValueName  = 'RunAsPPL'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'WN22_RestrictAnonymousSAM'
        {
            ValueName  = 'RestrictAnonymousSAM'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        RegistryPolicyFile 'WN22_LDAPClientSigning'
        {
            ValueName  = 'LDAPClientIntegrity'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
        }

        RegistryPolicyFile 'WN22_SMBSigning'
        {
            ValueName  = 'RequireSecuritySignature'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        }

        RegistryPolicyFile 'WN22_WinRM_NoBasic'
        {
            ValueName  = 'AllowBasic'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        }

        RegistryPolicyFile 'WN22_RDP_NLA'
        {
            ValueName  = 'UserAuthentication'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        }

        UserRightsAssignment 'WN22_DenyGuestNetwork'
        {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = @('Guests')
        }

        UserRightsAssignment 'WN22_DenyGuestLocal'
        {
            Policy   = 'Deny_log_on_locally'
            Identity = @('Guests')
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_WinSvr_2022_MS_and_DC_STIG_Computer_v2r1 -OutputPath 'C:\DSC\DoD_WinSvr_2022_MS_and_DC_STIG_Computer_v2r1'
