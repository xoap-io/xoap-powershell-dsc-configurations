Configuration 'DoD_Mozilla_Firefox_STIG_Computer_v6r5'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
	
     Node 'DoD_Mozilla_Firefox_STIG_Computer_v6r5'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              ValueData = 'tls1.2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\ExtensionUpdate'
         {
              ValueName = 'ExtensionUpdate'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFormHistory'
         {
              ValueName = 'DisableFormHistory'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableTelemetry'
         {
              ValueName = 'DisableTelemetry'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableDeveloperTools'
         {
              ValueName = 'DisableDeveloperTools'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableForgetButton'
         {
              ValueName = 'DisableForgetButton'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePrivateBrowsing'
         {
              ValueName = 'DisablePrivateBrowsing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SearchSuggestEnabled'
         {
              ValueName = 'SearchSuggestEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\NetworkPrediction'
         {
              ValueName = 'NetworkPrediction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxAccounts'
         {
              ValueName = 'DisableFirefoxAccounts'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFeedbackCommands'
         {
              ValueName = 'DisableFeedbackCommands'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Preferences'
         {
              ValueName = 'Preferences'
              ValueData = '{  "security.default_personal_cert": {    "Value": "Ask Every Time",    "Status": "locked"  },  "browser.search.update": {    "Value": false,    "Status": "locked"  },  "dom.disable_window_move_resize": {    "Value": true,    "Status": "locked"  },  "dom.disable_window_flip": {    "Value": true,    "Status": "locked"  },   "browser.contentblocking.category": {    "Value": "strict",   "Status": "locked"  },  "extensions.htmlaboutaddons.recommendations.enabled": {    "Value": false,    "Status": "locked"  }}'
              ValueType = 'MultiString'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePocket'
         {
              ValueName = 'DisablePocket'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxStudies'
         {
              ValueName = 'DisableFirefoxStudies'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots'
         {
              ValueName = 'ImportEnterpriseRoots'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\Certificates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisabledCiphers\TLS_RSA_WITH_3DES_EDE_CBC_SHA'
         {
              ValueName = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\DisabledCiphers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Fingerprinting'
         {
              ValueName = 'Fingerprinting'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Cryptomining'
         {
              ValueName = 'Cryptomining'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Enabled'
         {
              ValueName = 'Enabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Locked'
         {
              ValueName = 'Locked'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Search'
         {
              ValueName = 'Search'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\TopSites'
         {
              ValueName = 'TopSites'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredTopSites'
         {
              ValueName = 'SponsoredTopSites'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Highlights'
         {
              ValueName = 'Highlights'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Pocket'
         {
              ValueName = 'Pocket'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredPocket'
         {
              ValueName = 'SponsoredPocket'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Snippets'
         {
              ValueName = 'Snippets'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Locked'
         {
              ValueName = 'Locked'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission\Default'
         {
              ValueName = 'Default'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\InstallAddonsPermission'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Permissions\Autoplay\Default'
         {
              ValueName = 'Default'
              ValueData = 'block-audio-video'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\Permissions\Autoplay'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Default'
         {
              ValueName = 'Default'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Locked'
         {
              ValueName = 'Locked'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\1'
         {
              ValueName = '1'
              ValueData = '.mil'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\2'
         {
              ValueName = '2'
              ValueData = '.gov'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cache'
         {
              ValueName = 'Cache'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cookies'
         {
              ValueName = 'Cookies'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Downloads'
         {
              ValueName = 'Downloads'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\FormData'
         {
              ValueName = 'FormData'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\History'
         {
              ValueName = 'History'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Sessions'
         {
              ValueName = 'Sessions'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\SiteSettings'
         {
              ValueName = 'SiteSettings'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\OfflineApps'
         {
              ValueName = 'OfflineApps'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Locked'
         {
              ValueName = 'Locked'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging\ExtensionRecommendations'
         {
              ValueName = 'ExtensionRecommendations'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'Software\Policies\Mozilla\Firefox\UserMessaging'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
