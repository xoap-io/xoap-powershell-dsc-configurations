
Configuration 'MSTF_SecurityBaseline_W2K16_Member_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'MSTF_SecurityBaseline_W2K16_Member_Server'
	{
         RegistryPolicyFile 'NoDriveTypeAutoRun'
         {
              ValueName = 'NoDriveTypeAutoRun'
              ValueData = 255
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

         RegistryPolicyFile 'NoAutorun'
         {
              ValueName = 'NoAutorun'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

         RegistryPolicyFile 'DisableAutomaticRestartSignOn'
         {
              ValueName = 'DisableAutomaticRestartSignOn'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'LocalAccountTokenFilterPolicy'
         {
              ValueName = 'LocalAccountTokenFilterPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'EnhancedAntiSpoofing'
         {
              ValueName = 'EnhancedAntiSpoofing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
         }

         RegistryPolicyFile 'MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
         }

         RegistryPolicyFile 'MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
         }

         RegistryPolicyFile 'MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
         }

         RegistryPolicyFile 'NoAutoplayfornonVolume'
         {
              ValueName = 'NoAutoplayfornonVolume'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'NoDataExecutionPrevention'
         {
              ValueName = 'NoDataExecutionPrevention'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'NoHeapTerminationOnCorruption'
         {
              ValueName = 'NoHeapTerminationOnCorruption'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'NoBackgroundPolicy'
         {
              ValueName = 'NoBackgroundPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'NoGPOListChanges'
         {
              ValueName = 'NoGPOListChanges'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'AlwaysInstallElevated'
         {
              ValueName = 'AlwaysInstallElevated'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'EnableUserControl'
         {
              ValueName = 'EnableUserControl'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'AllowInsecureGuestAuth'
         {
              ValueName = 'AllowInsecureGuestAuth'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
         }

         RegistryPolicyFile 'SYSVOL'
         {
              ValueName = '\\*\SYSVOL'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
         }

         RegistryPolicyFile 'NETLOGON'
         {
              ValueName = '\\*\NETLOGON'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
         }

         RegistryPolicyFile 'NoLockScreenCamera'
         {
              ValueName = 'NoLockScreenCamera'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'NoLockScreenSlideshow'
         {
              ValueName = 'NoLockScreenSlideshow'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'EnableScriptBlockLogging'
         {
              ValueName = 'EnableScriptBlockLogging'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              ValueName = 'EnableScriptBlockInvocationLogging'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'DontDisplayNetworkSelectionUI'
         {
              ValueName = 'DontDisplayNetworkSelectionUI'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'EnumerateLocalUsers'
         {
              ValueName = 'EnumerateLocalUsers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'EnableSmartScreen'
         {
              ValueName = 'EnableSmartScreen'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'AllowIndexingEncryptedStoresOrItems'
         {
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'AllowDigest'
         {
              ValueName = 'AllowDigest'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'DisableRunAs'
         {
              ValueName = 'DisableRunAs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'MitigationOptions_FontBocking'
         {
              ValueName = 'MitigationOptions_FontBocking'
              ValueData = '1000000000000'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\MitigationOptions'
         }

         RegistryPolicyFile 'RestrictRemoteClients'
         {
              ValueName = 'RestrictRemoteClients'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
         }

         RegistryPolicyFile 'DisablePasswordSaving'
         {
              ValueName = 'DisablePasswordSaving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'fDisableCdm'
         {
              ValueName = 'fDisableCdm'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'fPromptForPassword'
         {
              ValueName = 'fPromptForPassword'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'fEncryptRPCTraffic'
         {
              ValueName = 'fEncryptRPCTraffic'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'MinEncryptionLevel'
         {
              ValueName = 'MinEncryptionLevel'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'PolicyVersion'
         {
              ValueName = 'PolicyVersion'
              ValueData = 538
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
         }

         RegistryPolicyFile 'DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'AdmPwdEnabled'
         {
              ValueName = 'AdmPwdEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
         }

         RegistryPolicyFile 'UseLogonCredential'
         {
              ValueName = 'UseLogonCredential'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
         }

         RegistryPolicyFile 'DriverLoadPolicy'
         {
              ValueName = 'DriverLoadPolicy'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
         }

         RegistryPolicyFile 'NoNameReleaseOnDemand'
         {
              ValueName = 'NoNameReleaseOnDemand'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
         }

         RegistryPolicyFile 'EnableICMPRedirect'
         {
              ValueName = 'EnableICMPRedirect'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
         }

         AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
         {
              Name = 'Credential Validation'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
         {
              Name = 'Credential Validation'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
         {
              Name = 'Other Account Management Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
         {
              Name = 'Other Account Management Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
         {
              Name = 'User Account Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
         {
              Name = 'User Account Management'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
         {
              Name = 'Plug and Play Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
         {
              Name = 'Plug and Play Events'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
         {
              Name = 'Process Creation'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
         {
              Name = 'Process Creation'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
         {
              Name = 'Group Membership'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
         {
              Name = 'Group Membership'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
         {
              Name = 'Logon'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
         {
              Name = 'Logon'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
         {
              Name = 'Special Logon'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
         {
              Name = 'Special Logon'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
         {
              Name = 'Removable Storage'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
         {
              Name = 'Removable Storage'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
         {
              Name = 'Audit Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
         {
              Name = 'Audit Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
         {
              Name = 'Authentication Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
         {
              Name = 'Authentication Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
         {
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
         {
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
         {
              Name = 'Other System Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
         {
              Name = 'Other System Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
         {
              Name = 'Security State Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
         {
              Name = 'Security State Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
         {
              Name = 'Security System Extension'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
         {
              Name = 'Security System Extension'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
         {
              Name = 'System Integrity'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
         {
              Name = 'System Integrity'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-6', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Policy = 'Deny_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Policy = 'Back_up_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Policy = 'Create_symbolic_links'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Force = $True
              Identity = @('*S-1-5-32-546', '*S-1-5-113')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Policy = 'Lock_pages_in_memory'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Policy = 'Increase_scheduling_priority'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Policy = 'Restore_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Policy = 'Create_a_token_object'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Policy = 'Create_permanent_shared_objects'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Policy = 'Create_global_objects'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-6', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-114', '*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-11', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Policy = 'Generate_security_audits'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Accounts_Guest_account_status = 'Disabled'
              Name = 'Accounts_Guest_account_status'
         }

         SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
         {
              Name = 'Network_security_Force_logoff_when_logon_hours_expire'
              Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         {
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
         {
              Name = 'Interactive_logon_Smart_card_removal_behavior'
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         {
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
         {
              Name = 'Domain_member_Disable_machine_account_password_changes'
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         {
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
         {
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         {
              System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
              Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         {
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
         {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
         {
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
         {
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         {
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
         {
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
              Name = 'Network_security_LAN_Manager_authentication_level'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         {
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
         {
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
         {
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         {
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         {
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
         {
              Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'O:BAG:BAD:(A;;RC;;;BA)'
              Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
         {
              Name = 'Network_security_LDAP_client_signing_requirements'
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Name = 'Domain_member_Maximum_machine_account_password_age'
              Domain_member_Maximum_machine_account_password_age = '30'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
         {
              Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
              Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         {
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
         {
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         {
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
         {
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
         {
              Interactive_logon_Machine_inactivity_limit = '900'
              Name = 'Interactive_logon_Machine_inactivity_limit'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
