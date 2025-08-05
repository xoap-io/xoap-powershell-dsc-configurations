
Configuration 'MSTF_SecurityBaseline_W11_Domain_Security'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_Domain_Security'
     {
         # Resets account lockout counter after 15 minutes to mitigate brute-force attacks
         AccountPolicy 'Reset_account_lockout_counter_after'
         {
             Reset_account_lockout_counter_after = 15
             Name = 'Reset_account_lockout_counter_after'
         }

         # Sets account lockout threshold to 10 invalid attempts
         AccountPolicy 'Account_lockout_threshold'
         {
             Name = 'Account_lockout_threshold'
             Account_lockout_threshold = 10
         }

         # Enforces password complexity requirements
         AccountPolicy 'Password_must_meet_complexity_requirements'
         {
             Name = 'Password_must_meet_complexity_requirements'
             Password_must_meet_complexity_requirements = 'Enabled'
         }

         # Sets account lockout duration to 15 minutes
         AccountPolicy 'Account_lockout_duration'
         {
             Name = 'Account_lockout_duration'
             Account_lockout_duration = 15
         }

         # Enforces password history to prevent reuse (24 previous passwords)
         AccountPolicy 'Enforce_password_history'
         {
             Name = 'Enforce_password_history'
             Enforce_password_history = 24
         }

         # Disables storing passwords using reversible encryption
         AccountPolicy 'Store_passwords_using_reversible_encryption'
         {
             Name = 'Store_passwords_using_reversible_encryption'
             Store_passwords_using_reversible_encryption = 'Disabled'
         }

         # Sets minimum password length to 14 characters
         AccountPolicy 'Minimum_Password_Length'
         {
             Name = 'Minimum_Password_Length'
             Minimum_Password_Length = 14
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
    }
