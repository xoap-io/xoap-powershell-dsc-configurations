# DSC Configuration: MSTF_SecurityBaseline_W11_24H2_Domain_Security
# Purpose: Applies domain account and Kerberos security settings for Windows 11 24H2.
Configuration 'MSTF_SecurityBaseline_W11_24H2_Domain_Security'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'
    Import-DSCResource -ModuleName 'SecurityPolicyDSC'    -ModuleVersion '2.10.0.0'

    Node 'MSTF_SecurityBaseline_W11_24H2_Domain_Security'
    {
        AccountPolicy 'DomainAccountPolicies'
        {
            Name                                        = 'DomainAccountPolicies'
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

        RegistryPolicyFile 'Kerberos_MaxTicketAge'
        {
            ValueName  = 'MaxTicketAge'
            ValueData  = 10
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        }

        RegistryPolicyFile 'Kerberos_MaxRenewAge'
        {
            ValueName  = 'MaxRenewAge'
            ValueData  = 7
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        }

        RegistryPolicyFile 'Kerberos_MaxServiceAge'
        {
            ValueName  = 'MaxServiceAge'
            ValueData  = 600
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        }

        RegistryPolicyFile 'Kerberos_MaxClockSkew'
        {
            ValueName  = 'MaxClockSkew'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W11_24H2_Domain_Security -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W11_24H2_Domain_Security'
