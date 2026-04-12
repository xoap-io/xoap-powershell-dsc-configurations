Configuration 'DoD_Windows_10_STIG_Computer_v2r7'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'AuditPolicyDSC'       -ModuleVersion '1.4.0.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'    -ModuleVersion '2.10.0.0'

    Node 'DoD_Windows_10_STIG_Computer_v2r7'
    {
        # WN10-00-000005: Domain-joined systems require authentication
        RegistryPolicyFile 'WN10_00_000005'
        {
            ValueName  = 'RequireSignOrSeal'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        # WN10-00-000010: Outgoing secure channel traffic must be signed
        RegistryPolicyFile 'WN10_00_000010'
        {
            ValueName  = 'SealSecureChannel'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        # WN10-00-000015: Outgoing secure channel traffic must be encrypted when possible
        RegistryPolicyFile 'WN10_00_000015'
        {
            ValueName  = 'SignSecureChannel'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        # WN10-AC-000005: Enforce password history = 24
        AccountPolicy 'WN10_PasswordPolicy'
        {
            Name                                        = 'WN10_PasswordPolicy'
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

        # WN10-AU-000005: Audit Credential Validation
        AuditPolicySubcategory 'WN10_AU_000005_Success'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN10_AU_000005_Failure'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # WN10-AU-000045: Audit Logon events
        AuditPolicySubcategory 'WN10_AU_000045_Success'
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'WN10_AU_000045_Failure'
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # WN10-AU-000100: Audit Process Creation
        AuditPolicySubcategory 'WN10_AU_000100'
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # WN10-CC-000005: Camera access from lock screen must be disabled
        RegistryPolicyFile 'WN10_CC_000005'
        {
            ValueName  = 'AllowCameraAboveLock'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
        }

        # WN10-CC-000020: Autoplay must be disabled for all drives
        RegistryPolicyFile 'WN10_CC_000020'
        {
            ValueName  = 'NoDriveTypeAutoRun'
            ValueData  = 255
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

        # WN10-CC-000025: Autorun commands must be disabled
        RegistryPolicyFile 'WN10_CC_000025'
        {
            ValueName  = 'NoAutorun'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

        # WN10-CC-000035: Microsoft accounts must be prevented from authentication
        RegistryPolicyFile 'WN10_CC_000035'
        {
            ValueName  = 'NoConnectedUser'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        # WN10-CC-000190: Solicited Remote Assistance must not be allowed
        RegistryPolicyFile 'WN10_CC_000190'
        {
            ValueName  = 'fAllowToGetHelp'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        }

        # WN10-CC-000200: Unauthenticated RPC clients must be restricted
        RegistryPolicyFile 'WN10_CC_000200'
        {
            ValueName  = 'RestrictRemoteClients'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        }

        # WN10-CC-000205: Windows Telemetry must be configured to Security or Basic
        RegistryPolicyFile 'WN10_CC_000205'
        {
            ValueName  = 'AllowTelemetry'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        }

        # WN10-CC-000225: IE Enhanced Protected Mode must be enabled
        RegistryPolicyFile 'WN10_CC_000225'
        {
            ValueName  = 'Isolation64Bit'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
        }

        # WN10-CC-000295: Windows SmartScreen must be enabled
        RegistryPolicyFile 'WN10_CC_000295'
        {
            ValueName  = 'EnableSmartScreen'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        }

        # WN10-SO-000005: Deny access to this computer from the network for guests
        UserRightsAssignment 'WN10_SO_000005_DenyGuestNetwork'
        {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = @('Guests', 'Local account and member of Administrators group')
        }

        # WN10-SO-000010: Guest account must be disabled (deny local logon)
        UserRightsAssignment 'WN10_SO_000010'
        {
            Policy   = 'Deny_log_on_locally'
            Identity = @('Guests')
        }

        # WN10-SO-000070: Windows must be configured to require a strong session key
        RegistryPolicyFile 'WN10_SO_000070'
        {
            ValueName  = 'RequireStrongKey'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        }

        # WN10-SO-000075: NTLMv2 only
        RegistryPolicyFile 'WN10_SO_000075'
        {
            ValueName  = 'LmCompatibilityLevel'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # WN10-SO-000080: LDAP signing required
        RegistryPolicyFile 'WN10_SO_000080'
        {
            ValueName  = 'LDAPClientIntegrity'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
        }

        # WN10-SO-000100: Anonymous enumeration of SAM accounts not allowed
        RegistryPolicyFile 'WN10_SO_000100'
        {
            ValueName  = 'RestrictAnonymousSAM'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # WN10-SO-000105: Anonymous enumeration of shares not allowed
        RegistryPolicyFile 'WN10_SO_000105'
        {
            ValueName  = 'RestrictAnonymous'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        }

        # WN10-SO-000130: Smart card removal behavior
        RegistryPolicyFile 'WN10_SO_000130'
        {
            ValueName  = 'ScRemoveOption'
            ValueData  = '1'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        }

        # WN10-SO-000140: Screen saver timeout (HKCU -> UserConfiguration)
        RegistryPolicyFile 'WN10_SO_000140'
        {
            ValueName  = 'ScreenSaveTimeOut'
            ValueData  = '900'
            ValueType  = 'String'
            TargetType = 'UserConfiguration'
            Key        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
        }

        # WN10-SO-000145: Screen saver password (HKCU -> UserConfiguration)
        RegistryPolicyFile 'WN10_SO_000145'
        {
            ValueName  = 'ScreenSaverIsSecure'
            ValueData  = '1'
            ValueType  = 'String'
            TargetType = 'UserConfiguration'
            Key        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_Windows_10_STIG_Computer_v2r7 -OutputPath 'C:\DSC\DoD_Windows_10_STIG_Computer_v2r7'
