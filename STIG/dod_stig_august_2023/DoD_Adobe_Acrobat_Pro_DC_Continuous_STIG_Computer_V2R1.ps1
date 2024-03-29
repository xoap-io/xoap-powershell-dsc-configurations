Configuration 'DoD_Adobe_Acrobat_Pro_DC_Continuous_STIG_Computer_V2R1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
	
     Node 'DoD_Adobe_Acrobat_Pro_DC_Continuous_STIG_Computer_V2R1'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityStandalone'
         {
              ValueName = 'bEnhancedSecurityStandalone'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
         {
              ValueName = 'bEnhancedSecurityInBrowser'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iFileAttachmentPerms'
         {
              ValueName = 'iFileAttachmentPerms'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnableFlash'
         {
              ValueName = 'bEnableFlash'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedFolders'
         {
              ValueName = 'bDisableTrustedFolders'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bProtectedMode'
         {
              ValueName = 'bProtectedMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iProtectedView'
         {
              ValueName = 'iProtectedView'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
         {
              ValueName = 'bDisablePDFHandlerSwitching'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedSites'
         {
              ValueName = 'bDisableTrustedSites'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
         {
              ValueName = 'bAdobeSendPluginToggle'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bDisableADCFileStore'
         {
              ValueName = 'bDisableADCFileStore'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
         {
              ValueName = 'iUnknownURLPerms'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
         {
              ValueName = 'iURLPerms'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bTogglePrefsSync'
         {
              ValueName = 'bTogglePrefsSync'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bToggleWebConnectors'
         {
              ValueName = 'bToggleWebConnectors'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
         {
              ValueName = 'bDisableSharePointFeatures'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
         {
              ValueName = 'bDisableWebmail'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
         {
              ValueName = 'bShowWelcomeScreen'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
         {
              ValueName = 'DisableMaintenance'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral\bFIPSMode'
         {
              ValueName = 'bFIPSMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\AVGeneral'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload\bLoadSettingsFromURL'
         {
              ValueName = 'bLoadSettingsFromURL'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\SOFTWARE\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload'
         }#>

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
