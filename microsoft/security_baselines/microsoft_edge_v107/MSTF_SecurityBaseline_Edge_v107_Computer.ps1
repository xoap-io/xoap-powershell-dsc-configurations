
Configuration 'MSTF_SecurityBaseline_Edge_v107_Computer'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_Edge_v107_Computer'
     {
         # Isolates sites in separate processes for security
         RegistryPolicyFile 'SitePerProcess'
         {
              ValueName = 'SitePerProcess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enforces minimum SSL version to TLS 1.2
         RegistryPolicyFile 'SSLVersionMin'
         {
              ValueName = 'SSLVersionMin'
              ValueData = 'tls1.2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Restricts authentication schemes to NTLM and Negotiate
         RegistryPolicyFile 'AuthSchemes'
         {
              ValueName = 'AuthSchemes'
              ValueData = 'ntlm,negotiate'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables user-level native messaging hosts
         RegistryPolicyFile 'NativeMessagingUserLevelHosts'
         {
              ValueName = 'NativeMessagingUserLevelHosts'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables password manager
         RegistryPolicyFile 'PasswordManagerEnabled'
         {
              ValueName = 'PasswordManagerEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables SmartScreen for phishing/malware protection
         RegistryPolicyFile 'SmartScreenEnabled'
         {
              ValueName = 'SmartScreenEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Prevents users from overriding SmartScreen warnings
         RegistryPolicyFile 'PreventSmartScreenPromptOverride'
         {
              ValueName = 'PreventSmartScreenPromptOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Prevents users from overriding SmartScreen warnings for files
         RegistryPolicyFile 'PreventSmartScreenPromptOverrideForFiles'
         {
              ValueName = 'PreventSmartScreenPromptOverrideForFiles'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables SSL error override
         RegistryPolicyFile 'SSLErrorOverrideAllowed'
         {
              ValueName = 'SSLErrorOverrideAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables SmartScreen PUA protection
         RegistryPolicyFile 'SmartScreenPuaEnabled'
         {
              ValueName = 'SmartScreenPuaEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables basic auth over HTTP
         RegistryPolicyFile 'BasicAuthOverHttpEnabled'
         {
              ValueName = 'BasicAuthOverHttpEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables IE mode reload
         RegistryPolicyFile 'InternetExplorerIntegrationReloadInIEModeAllowed'
         {
              ValueName = 'InternetExplorerIntegrationReloadInIEModeAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables unrestricted access to SharedArrayBuffer
         RegistryPolicyFile 'SharedArrayBufferUnrestrictedAccessAllowed'
         {
              ValueName = 'SharedArrayBufferUnrestrictedAccessAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables insecure private network requests
         RegistryPolicyFile 'InsecurePrivateNetworkRequestsAllowed'
         {
              ValueName = 'InsecurePrivateNetworkRequestsAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables legacy TripleDES cipher
         RegistryPolicyFile 'TripleDESEnabled'
         {
              ValueName = 'TripleDESEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Blocks legacy extension points
         RegistryPolicyFile 'BrowserLegacyExtensionPointsBlockingEnabled'
         {
              ValueName = 'BrowserLegacyExtensionPointsBlockingEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables display capture permissions policy
         RegistryPolicyFile 'DisplayCapturePermissionsPolicyEnabled'
         {
              ValueName = 'DisplayCapturePermissionsPolicyEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables IE mode toolbar button
         RegistryPolicyFile 'InternetExplorerModeToolbarButtonEnabled'
         {
              ValueName = 'InternetExplorerModeToolbarButtonEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables typosquatting checker
         RegistryPolicyFile 'TyposquattingCheckerEnabled'
         {
              ValueName = 'TyposquattingCheckerEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # --- Edge Security Baseline Policies ---
         # Isolates sites in separate processes for security
         RegistryPolicyFile 'SitePerProcess' {
              ValueName = 'SitePerProcess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enforces minimum SSL version to TLS 1.2
         RegistryPolicyFile 'SSLVersionMin' {
              ValueName = 'SSLVersionMin'
              ValueData = 'tls1.2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Restricts authentication schemes to NTLM and Negotiate
         RegistryPolicyFile 'AuthSchemes' {
              ValueName = 'AuthSchemes'
              ValueData = 'ntlm,negotiate'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables user-level native messaging hosts
         RegistryPolicyFile 'NativeMessagingUserLevelHosts' {
              ValueName = 'NativeMessagingUserLevelHosts'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables password manager
         RegistryPolicyFile 'PasswordManagerEnabled' {
              ValueName = 'PasswordManagerEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables SmartScreen for phishing/malware protection
         RegistryPolicyFile 'SmartScreenEnabled' {
              ValueName = 'SmartScreenEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Prevents users from overriding SmartScreen warnings
         RegistryPolicyFile 'PreventSmartScreenPromptOverride' {
              ValueName = 'PreventSmartScreenPromptOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }
         # Prevents users from overriding SmartScreen warnings for files
         RegistryPolicyFile 'PreventSmartScreenPromptOverrideForFiles' {
              ValueName = 'PreventSmartScreenPromptOverrideForFiles'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables SSL error override
         RegistryPolicyFile 'SSLErrorOverrideAllowed' {
              ValueName = 'SSLErrorOverrideAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables SmartScreen PUA protection
         RegistryPolicyFile 'SmartScreenPuaEnabled' {
              ValueName = 'SmartScreenPuaEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables basic auth over HTTP
         RegistryPolicyFile 'BasicAuthOverHttpEnabled' {
              ValueName = 'BasicAuthOverHttpEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables IE mode reload
         RegistryPolicyFile 'InternetExplorerIntegrationReloadInIEModeAllowed' {
              ValueName = 'InternetExplorerIntegrationReloadInIEModeAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables unrestricted access to SharedArrayBuffer
         RegistryPolicyFile 'SharedArrayBufferUnrestrictedAccessAllowed' {
              ValueName = 'SharedArrayBufferUnrestrictedAccessAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables insecure private network requests
         RegistryPolicyFile 'InsecurePrivateNetworkRequestsAllowed' {
              ValueName = 'InsecurePrivateNetworkRequestsAllowed'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables legacy TripleDES cipher
         RegistryPolicyFile 'TripleDESEnabled' {
              ValueName = 'TripleDESEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }
         # Blocks legacy extension points
         RegistryPolicyFile 'BrowserLegacyExtensionPointsBlockingEnabled' {
              ValueName = 'BrowserLegacyExtensionPointsBlockingEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables display capture permissions policy
         RegistryPolicyFile 'DisplayCapturePermissionsPolicyEnabled' {
              ValueName = 'DisplayCapturePermissionsPolicyEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables IE mode toolbar button
         RegistryPolicyFile 'InternetExplorerModeToolbarButtonEnabled' {
              ValueName = 'InternetExplorerModeToolbarButtonEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Enables typosquatting checker
         RegistryPolicyFile 'TyposquattingCheckerEnabled' {
              ValueName = 'TyposquattingCheckerEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables Edge image enhancement
         RegistryPolicyFile 'EdgeEnhanceImagesEnabled' {
              ValueName = 'EdgeEnhanceImagesEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables U2F security key API
         RegistryPolicyFile 'U2fSecurityKeyApiEnabled' {
              ValueName = 'U2fSecurityKeyApiEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Disables WebSQL access
         RegistryPolicyFile 'WebSQLAccess' {
              ValueName = 'WebSQLAccess'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }

         # Blocks all extension installs by default
         RegistryPolicyFile 'ExtensionInstallBlocklist' {
              ValueName = '1'
              ValueData = '*'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
         }
     }
}
