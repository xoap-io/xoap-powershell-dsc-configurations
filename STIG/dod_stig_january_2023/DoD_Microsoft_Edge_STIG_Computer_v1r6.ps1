
Configuration 'DoD_Microsoft_Edge_STIG_Computer_v1r6'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_Microsoft_Edge_STIG_Computer_v1r6'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              ValueData = 'tls1.2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SyncDisabled'
         {
              ValueName = 'SyncDisabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportBrowserSettings'
         {
              ValueName = 'ImportBrowserSettings'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DeveloperToolsAvailability'
         {
              ValueName = 'DeveloperToolsAvailability'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PromptForDownloadLocation'
         {
              ValueName = 'PromptForDownloadLocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride'
         {
              ValueName = 'PreventSmartScreenPromptOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles'
         {
              ValueName = 'PreventSmartScreenPromptOverrideForFiles'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\InPrivateModeAvailability'
         {
              ValueName = 'InPrivateModeAvailability'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AllowDeletingBrowserHistory'
         {
              ValueName = 'AllowDeletingBrowserHistory'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BackgroundModeEnabled'
         {
              ValueName = 'BackgroundModeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultPopupsSetting'
         {
              ValueName = 'DefaultPopupsSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\NetworkPredictionOptions'
         {
              ValueName = 'NetworkPredictionOptions'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportAutofillFormData'
         {
              ValueName = 'ImportAutofillFormData'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportCookies'
         {
              ValueName = 'ImportCookies'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportExtensions'
         {
              ValueName = 'ImportExtensions'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHistory'
         {
              ValueName = 'ImportHistory'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHomepage'
         {
              ValueName = 'ImportHomepage'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportOpenTabs'
         {
              ValueName = 'ImportOpenTabs'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportPaymentInfo'
         {
              ValueName = 'ImportPaymentInfo'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSavedPasswords'
         {
              ValueName = 'ImportSavedPasswords'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSearchEngine'
         {
              ValueName = 'ImportSearchEngine'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportShortcuts'
         {
              ValueName = 'ImportShortcuts'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowed'
         {
              ValueName = 'AutoplayAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableMediaRouter'
         {
              ValueName = 'EnableMediaRouter'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillCreditCardEnabled'
         {
              ValueName = 'AutofillCreditCardEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillAddressEnabled'
         {
              ValueName = 'AutofillAddressEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PersonalizationReportingEnabled'
         {
              ValueName = 'PersonalizationReportingEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultGeolocationSetting'
         {
              ValueName = 'DefaultGeolocationSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\IsolateOrigins'
         {
              ValueName = 'IsolateOrigins'
              ValueData = $null
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled'
         {
              ValueName = 'SmartScreenEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled'
         {
              ValueName = 'SmartScreenPuaEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PaymentMethodQueryEnabled'
         {
              ValueName = 'PaymentMethodQueryEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AlternateErrorPagesEnabled'
         {
              ValueName = 'AlternateErrorPagesEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\UserFeedbackAllowed'
         {
              ValueName = 'UserFeedbackAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EdgeCollectionsEnabled'
         {
              ValueName = 'EdgeCollectionsEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureShare'
         {
              ValueName = 'ConfigureShare'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BrowserGuestModeEnabled'
         {
              ValueName = 'BrowserGuestModeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BuiltInDnsClientEnabled'
         {
              ValueName = 'BuiltInDnsClientEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
         {
              ValueName = 'SitePerProcess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ManagedSearchEngines'
         {
              ValueName = 'ManagedSearchEngines'
              ValueData = '[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AuthSchemes'
         {
              ValueName = 'AuthSchemes'
              ValueData = 'ntlm,negotiate'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebUsbGuardSetting'
         {
              ValueName = 'DefaultWebUsbGuardSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebBluetoothGuardSetting'
         {
              ValueName = 'DefaultWebBluetoothGuardSetting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TrackingPrevention'
         {
              ValueName = 'TrackingPrevention'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\RelaunchNotification'
         {
              ValueName = 'RelaunchNotification'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ProxySettings'
         {
              ValueName = 'ProxySettings'
              ValueData = 'ADD YOUR PROXY CONFIGURATIONS HERE'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableOnlineRevocationChecks'
         {
              ValueName = 'EnableOnlineRevocationChecks'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\QuicAllowed'
         {
              ValueName = 'QuicAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DownloadRestrictions'
         {
              ValueName = 'DownloadRestrictions'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\1'
         {
              ValueName = '1'
              ValueData = '[*.]gov'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\2'
         {
              ValueName = '2'
              ValueData = '[*.]mil'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist\1'
         {
              ValueName = '1'
              ValueData = '*'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\1'
         {
              ValueName = '1'
              ValueData = '[*.]mil'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\2'
         {
              ValueName = '2'
              ValueData = '[*.]gov'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
