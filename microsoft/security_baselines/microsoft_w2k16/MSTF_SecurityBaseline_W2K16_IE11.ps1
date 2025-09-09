
Configuration 'MSTF_SecurityBaseline_W10_1607_IE11'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'MSTF_SecurityBaseline_W10_1607_IE11'
	{
         RegistryPolicyFile 'RunThisTimeEnabled'
         {
              ValueName = 'RunThisTimeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
         }

         RegistryPolicyFile 'VersionCheckEnabled'
         {
              ValueName = 'VersionCheckEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
         }

         RegistryPolicyFile 'RunInvalidSignatures'
         {
              ValueName = 'RunInvalidSignatures'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
         }

         RegistryPolicyFile 'CheckExeSignatures'
         {
              ValueName = 'CheckExeSignatures'
              ValueData = 'yes'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
         }

         RegistryPolicyFile 'DisableEnclosureDownload'
         {
              ValueName = 'DisableEnclosureDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
         }

         RegistryPolicyFile 'Isolation64Bit'
         {
              ValueName = 'Isolation64Bit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         RegistryPolicyFile 'DisableEPMCompat'
         {
              ValueName = 'DisableEPMCompat'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         RegistryPolicyFile 'Isolation'
         {
              ValueName = 'Isolation'
              ValueData = 'PMEM'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         RegistryPolicyFile '(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         RegistryPolicyFile 'explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         RegistryPolicyFile 'iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         RegistryPolicyFile 'PreventOverrideAppRepUnknown'
         {
              ValueName = 'PreventOverrideAppRepUnknown'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         RegistryPolicyFile 'PreventOverride'
         {
              ValueName = 'PreventOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         RegistryPolicyFile 'EnabledV9'
         {
              ValueName = 'EnabledV9'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         RegistryPolicyFile 'NoCrashDetection'
         {
              ValueName = 'NoCrashDetection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
         }

         RegistryPolicyFile 'DisableSecuritySettingsCheck'
         {
              ValueName = 'DisableSecuritySettingsCheck'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
         }

         RegistryPolicyFile 'BlockNonAdminActiveXInstall'
         {
              ValueName = 'BlockNonAdminActiveXInstall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
         }

         RegistryPolicyFile 'OnlyUseAXISForActiveXInstall'
         {
              ValueName = 'OnlyUseAXISForActiveXInstall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\AxInstaller'
         }

         RegistryPolicyFile 'Security_zones_map_edit'
         {
              ValueName = 'Security_zones_map_edit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Security_options_edit'
         {
              ValueName = 'Security_options_edit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Security_HKLM_only'
         {
              ValueName = 'Security_HKLM_only'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'CertificateRevocation'
         {
              ValueName = 'CertificateRevocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'PreventIgnoreCertErrors'
         {
              ValueName = 'PreventIgnoreCertErrors'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'WarnOnBadCertRecving'
         {
              ValueName = 'WarnOnBadCertRecving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'SecureProtocols'
         {
              ValueName = 'SecureProtocols'
              ValueData = 2688
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'EnableSSL3Fallback'
         {
              ValueName = 'EnableSSL3Fallback'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
         }

         RegistryPolicyFile '2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3'
         }

         RegistryPolicyFile '2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
         }

         RegistryPolicyFile 'UNCAsIntranet'
         {
              ValueName = 'UNCAsIntranet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
         }

         RegistryPolicyFile '270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
         }

         RegistryPolicyFile '270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         RegistryPolicyFile '1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         RegistryPolicyFile '270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         RegistryPolicyFile '1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         RegistryPolicyFile '2001'
         {
              ValueName = '2001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2102'
         {
              ValueName = '2102'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1802'
         {
              ValueName = '1802'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '160A'
         {
              ValueName = '160A'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1406'
         {
              ValueName = '1406'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1804'
         {
              ValueName = '1804'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2200'
         {
              ValueName = '2200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1209'
         {
              ValueName = '1209'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1206'
         {
              ValueName = '1206'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1809'
         {
              ValueName = '1809'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2500'
         {
              ValueName = '2500'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2103'
         {
              ValueName = '2103'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1604'
         {
              ValueName = '1604'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1606'
         {
              ValueName = '1606'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2402'
         {
              ValueName = '2402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2004'
         {
              ValueName = '2004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1001'
         {
              ValueName = '1001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1A00'
         {
              ValueName = '1A00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2708'
         {
              ValueName = '2708'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1004'
         {
              ValueName = '1004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '120b'
         {
              ValueName = '120b'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1407'
         {
              ValueName = '1407'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1409'
         {
              ValueName = '1409'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1607'
         {
              ValueName = '1607'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2709'
         {
              ValueName = '2709'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2101'
         {
              ValueName = '2101'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1806'
         {
              ValueName = '1806'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '120c'
         {
              ValueName = '120c'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile '1608'
         {
              ValueName = '1608'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1001'
         {
              ValueName = '1001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1607'
         {
              ValueName = '1607'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '120b'
         {
              ValueName = '120b'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1809'
         {
              ValueName = '1809'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1004'
         {
              ValueName = '1004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1606'
         {
              ValueName = '1606'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1407'
         {
              ValueName = '1407'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '160A'
         {
              ValueName = '160A'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1406'
         {
              ValueName = '1406'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2102'
         {
              ValueName = '2102'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2004'
         {
              ValueName = '2004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2200'
         {
              ValueName = '2200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2000'
         {
              ValueName = '2000'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1402'
         {
              ValueName = '1402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1803'
         {
              ValueName = '1803'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2402'
         {
              ValueName = '2402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1400'
         {
              ValueName = '1400'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1A00'
         {
              ValueName = '1A00'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2001'
         {
              ValueName = '2001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1604'
         {
              ValueName = '1604'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2500'
         {
              ValueName = '2500'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1409'
         {
              ValueName = '1409'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1209'
         {
              ValueName = '1209'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1206'
         {
              ValueName = '1206'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2708'
         {
              ValueName = '2708'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1802'
         {
              ValueName = '1802'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2103'
         {
              ValueName = '2103'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2709'
         {
              ValueName = '2709'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1405'
         {
              ValueName = '1405'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2101'
         {
              ValueName = '2101'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1200'
         {
              ValueName = '1200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1804'
         {
              ValueName = '1804'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '1806'
         {
              ValueName = '1806'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile '120c'
         {
              ValueName = '120c'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
