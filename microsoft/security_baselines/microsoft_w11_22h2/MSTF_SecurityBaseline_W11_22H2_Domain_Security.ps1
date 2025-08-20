
Configuration 'MSTF_SecurityBaseline_W11_22H2_Domain_Security'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_22H2_Domain_Security'
     {
        # Resets account lockout counter after 10 minutes
        AccountPolicy 'ResetLockoutCount'
        {
            Reset_account_lockout_counter_after = 10
            Name = 'Reset_account_lockout_counter_after'
        }

        # Sets account lockout threshold to 10 invalid attempts
        AccountPolicy 'LockoutBadCount'
        {
            Name = 'Account_lockout_threshold'
            Account_lockout_threshold = 10
        }

        # Enforces password complexity requirements
        AccountPolicy 'PasswordComplexity'
        {
            Name = 'Password_must_meet_complexity_requirements'
            Password_must_meet_complexity_requirements = 'Enabled'
        }

        # Sets account lockout duration to 10 minutes
        AccountPolicy 'LockoutDuration'
        {
            Name = 'Account_lockout_duration'
            Account_lockout_duration = 10
        }

        # Enforces password history to 24 passwords
        AccountPolicy 'PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }

        # Disables storing passwords using reversible encryption
        AccountPolicy 'ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 14
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
