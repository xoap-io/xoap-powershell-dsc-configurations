
Configuration 'DoD_Google_Chrome_STIG_Computer_v2r8'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_Google_Chrome_STIG_Computer_v2r8'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\RemoteAccessHostFirewallTraversal'
         {
              ValueName = 'RemoteAccessHostFirewallTraversal'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPopupsSetting'
         {
              ValueName = 'DefaultPopupsSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultGeolocationSetting'
         {
              ValueName = 'DefaultGeolocationSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderName'
         {
              ValueName = 'DefaultSearchProviderName'
              ValueData = 'Google Encrypted'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderEnabled'
         {
              ValueName = 'DefaultSearchProviderEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BackgroundModeEnabled'
         {
              ValueName = 'BackgroundModeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SyncDisabled'
         {
              ValueName = 'SyncDisabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\CloudPrintProxyEnabled'
         {
              ValueName = 'CloudPrintProxyEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\MetricsReportingEnabled'
         {
              ValueName = 'MetricsReportingEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportSavedPasswords'
         {
              ValueName = 'ImportSavedPasswords'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability'
         {
              ValueName = 'IncognitoModeAvailability'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SavingBrowserHistoryDisabled'
         {
              ValueName = 'SavingBrowserHistoryDisabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowDeletingBrowserHistory'
         {
              ValueName = 'AllowDeletingBrowserHistory'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PromptForDownloadLocation'
         {
              ValueName = 'PromptForDownloadLocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowed'
         {
              ValueName = 'AutoplayAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingExtendedReportingEnabled'
         {
              ValueName = 'SafeBrowsingExtendedReportingEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebUsbGuardSetting'
         {
              ValueName = 'DefaultWebUsbGuardSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupEnabled'
         {
              ValueName = 'ChromeCleanupEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupReportingEnabled'
         {
              ValueName = 'ChromeCleanupReportingEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableMediaRouter'
         {
              ValueName = 'EnableMediaRouter'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\UrlKeyedAnonymizedDataCollectionEnabled'
         {
              ValueName = 'UrlKeyedAnonymizedDataCollectionEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\WebRtcEventLogCollectionAllowed'
         {
              ValueName = 'WebRtcEventLogCollectionAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\NetworkPredictionOptions'
         {
              ValueName = 'NetworkPredictionOptions'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability'
         {
              ValueName = 'DeveloperToolsAvailability'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BrowserGuestModeEnabled'
         {
              ValueName = 'BrowserGuestModeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillCreditCardEnabled'
         {
              ValueName = 'AutofillCreditCardEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillAddressEnabled'
         {
              ValueName = 'AutofillAddressEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportAutofillFormData'
         {
              ValueName = 'ImportAutofillFormData'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingProtectionLevel'
         {
              ValueName = 'SafeBrowsingProtectionLevel'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderSearchURL'
         {
              ValueName = 'DefaultSearchProviderSearchURL'
              ValueData = 'https://www.google.com/search?q={searchTerms}'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions'
         {
              ValueName = 'DownloadRestrictions'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebBluetoothGuardSetting'
         {
              ValueName = 'DefaultWebBluetoothGuardSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\QuicAllowed'
         {
              ValueName = 'QuicAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableOnlineRevocationChecks'
         {
              ValueName = 'EnableOnlineRevocationChecks'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              ValueData = 'tls1.2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\AutoplayAllowlist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\1'
         {
              ValueName = '1'
              ValueData = '[*.]mil'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\2'
         {
              ValueName = '2'
              ValueData = '[*.]gov'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\CookiesSessionOnlyForUrls'
         }#>

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist\1'
         {
              ValueName = '1'
              ValueData = 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist\1'
         {
              ValueName = '1'
              ValueData = '*'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Google\Chrome\URLBlocklist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\URLBlocklist'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\URLBlocklist\1'
         {
              ValueName = '1'
              ValueData = 'javascript://*'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Google\Chrome\URLBlocklist'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
