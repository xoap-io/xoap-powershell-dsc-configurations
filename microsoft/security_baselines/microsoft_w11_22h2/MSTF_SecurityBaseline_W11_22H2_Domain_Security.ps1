
Configuration MSTF_SecurityBaseline_W11_22H2_Domain_Security
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

	Node MSTF_SecurityBaseline_W11_22H2_Domain_Security
	{
         AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Reset_account_lockout_counter_after = 10
              Name = 'Reset_account_lockout_counter_after'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Name = 'Account_lockout_threshold'
              Account_lockout_threshold = 10
         }

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Name = 'Account_lockout_duration'
              Account_lockout_duration = 10
         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Name = 'Enforce_password_history'
              Enforce_password_history = 24
         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
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
