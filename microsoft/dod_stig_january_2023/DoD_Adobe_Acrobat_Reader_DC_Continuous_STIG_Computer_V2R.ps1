
Configuration DoD_Adobe_Acrobat_Reader_DC_Continuous_STIG_Computer_V2R
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

	Node DoD_Adobe_Acrobat_Reader_DC_Continuous_STIG_Computer_V2R
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityStandalone'
         {
              ValueName = 'bEnhancedSecurityStandalone'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bProtectedMode'
         {
              ValueName = 'bProtectedMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iProtectedView'
         {
              ValueName = 'iProtectedView'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iFileAttachmentPerms'
         {
              ValueName = 'iFileAttachmentPerms'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnableFlash'
         {
              ValueName = 'bEnableFlash'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
         {
              ValueName = 'bDisablePDFHandlerSwitching'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bAcroSuppressUpsell'
         {
              ValueName = 'bAcroSuppressUpsell'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
         {
              ValueName = 'bEnhancedSecurityInBrowser'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedFolders'
         {
              ValueName = 'bDisableTrustedFolders'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedSites'
         {
              ValueName = 'bDisableTrustedSites'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
         {
              ValueName = 'bAdobeSendPluginToggle'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
         {
              ValueName = 'iURLPerms'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
         {
              ValueName = 'iUnknownURLPerms'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeDocumentServices'
         {
              ValueName = 'bToggleAdobeDocumentServices'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bTogglePrefsSync'
         {
              ValueName = 'bTogglePrefsSync'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleWebConnectors'
         {
              ValueName = 'bToggleWebConnectors'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeSign'
         {
              ValueName = 'bToggleAdobeSign'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bUpdater'
         {
              ValueName = 'bUpdater'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
         {
              ValueName = 'bDisableSharePointFeatures'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
         {
              ValueName = 'bDisableWebmail'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
         {
              ValueName = 'bShowWelcomeScreen'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
