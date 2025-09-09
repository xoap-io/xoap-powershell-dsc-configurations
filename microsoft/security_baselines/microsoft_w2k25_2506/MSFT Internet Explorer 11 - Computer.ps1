Configuration 'MSFT_InternetExplorer11_Computer'
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
     
	Node 'MSFT_InternetExplorer11_Computer'
	{
         # Disable "Run this time" for outdated ActiveX controls to prevent security risks
         RegistryPolicyFile 'RunThisTimeEnabled'
         {
              ValueName = 'RunThisTimeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
         }

         # Enable version checking for ActiveX controls to ensure up-to-date security
         RegistryPolicyFile 'VersionCheckEnabled'
         {
              ValueName = 'VersionCheckEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
         }

         # Block execution of files with invalid digital signatures from downloads
         RegistryPolicyFile 'RunInvalidSignatures'
         {
              ValueName = 'RunInvalidSignatures'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
         }

         # Require signature verification for executable downloads
         RegistryPolicyFile 'CheckExeSignatures'
         {
              ValueName = 'CheckExeSignatures'
              ValueData = 'yes'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
         }

         # Enable 64-bit Enhanced Protected Mode for better security isolation
         RegistryPolicyFile 'Isolation64Bit'
         {
              ValueName = 'Isolation64Bit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         # Disable Enhanced Protected Mode compatibility mode
         RegistryPolicyFile 'DisableEPMCompat'
         {
              ValueName = 'DisableEPMCompat'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         # Set process isolation to Protected Mode Enhanced Memory (PMEM)
         RegistryPolicyFile 'Isolation'
         {
              ValueName = 'Isolation'
              ValueData = 'PMEM'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         # Disable MK protocol support for Reserved applications (security risk)
         RegistryPolicyFile 'DisableMkProtocol_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         # Disable MK protocol support for Internet Explorer process
         RegistryPolicyFile 'DisableMkProtocol_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         # Disable MK protocol support for Windows Explorer process
         RegistryPolicyFile 'DisableMkProtocol_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         # Enable consistent MIME handling for Windows Explorer
         RegistryPolicyFile 'MimeHandling_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         # Enable consistent MIME handling for Internet Explorer
         RegistryPolicyFile 'MimeHandling_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         # Enable consistent MIME handling for Reserved applications
         RegistryPolicyFile 'MimeHandling_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         # Disable MIME sniffing for Windows Explorer (security hardening)
         RegistryPolicyFile 'DisableMimeSniffing_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         # Disable MIME sniffing for Internet Explorer (security hardening)
         RegistryPolicyFile 'DisableMimeSniffing_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         # Disable MIME sniffing for Reserved applications (security hardening)
         RegistryPolicyFile 'DisableMimeSniffing_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         # Restrict ActiveX installation for Reserved applications
         RegistryPolicyFile 'RestrictActiveXInstall_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         # Restrict ActiveX installation for Windows Explorer
         RegistryPolicyFile 'RestrictActiveXInstall_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         # Restrict ActiveX installation for Internet Explorer
         RegistryPolicyFile 'RestrictActiveXInstall_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         # Restrict file downloads for Reserved applications
         RegistryPolicyFile 'RestrictFileDownload_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         # Restrict file downloads for Internet Explorer
         RegistryPolicyFile 'RestrictFileDownload_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         # Restrict file downloads for Windows Explorer
         RegistryPolicyFile 'RestrictFileDownload_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         # Enable security band display for Reserved applications
         RegistryPolicyFile 'SecurityBand_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         # Enable security band display for Internet Explorer
         RegistryPolicyFile 'SecurityBand_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         # Enable security band display for Windows Explorer
         RegistryPolicyFile 'SecurityBand_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         # Enable window restrictions for Internet Explorer (popup blocking)
         RegistryPolicyFile 'WindowRestrictions_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         # Enable window restrictions for Reserved applications (popup blocking)
         RegistryPolicyFile 'WindowRestrictions_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         # Enable window restrictions for Windows Explorer (popup blocking)
         RegistryPolicyFile 'WindowRestrictions_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         # Prevent zone elevation for Reserved applications
         RegistryPolicyFile 'PreventZoneElevation_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         # Prevent zone elevation for Windows Explorer
         RegistryPolicyFile 'PreventZoneElevation_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         # Prevent zone elevation for Internet Explorer
         RegistryPolicyFile 'PreventZoneElevation_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         # Prevent override of SmartScreen Application Reputation warnings
         RegistryPolicyFile 'PreventOverrideAppRepUnknown'
         {
              ValueName = 'PreventOverrideAppRepUnknown'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         # Prevent override of SmartScreen warnings
         RegistryPolicyFile 'PreventOverride'
         {
              ValueName = 'PreventOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         # Enable SmartScreen Filter version 9
         RegistryPolicyFile 'EnabledV9'
         {
              ValueName = 'EnabledV9'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         # Disable crash detection to prevent information disclosure
         RegistryPolicyFile 'NoCrashDetection'
         {
              ValueName = 'NoCrashDetection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
         }

         # Enable security settings check (do not disable security warnings)
         RegistryPolicyFile 'DisableSecuritySettingsCheck'
         {
              ValueName = 'DisableSecuritySettingsCheck'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
         }

         # Block non-administrator ActiveX control installation
         RegistryPolicyFile 'BlockNonAdminActiveXInstall'
         {
              ValueName = 'BlockNonAdminActiveXInstall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
         }

         # Use only AXIS (ActiveX Installer Service) for ActiveX installation
         RegistryPolicyFile 'OnlyUseAXISForActiveXInstall'
         {
              ValueName = 'OnlyUseAXISForActiveXInstall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\AxInstaller'
         }

         # Lock down security zone mapping editing
         RegistryPolicyFile 'SecurityZonesMapEdit'
         {
              ValueName = 'Security_zones_map_edit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Lock down security options editing
         RegistryPolicyFile 'SecurityOptionsEdit'
         {
              ValueName = 'Security_options_edit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Use only HKLM security settings (prevent user overrides)
         RegistryPolicyFile 'SecurityHKLMOnly'
         {
              ValueName = 'Security_HKLM_only'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Enable certificate revocation checking
         RegistryPolicyFile 'CertificateRevocation'
         {
              ValueName = 'CertificateRevocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Prevent ignoring certificate errors
         RegistryPolicyFile 'PreventIgnoreCertErrors'
         {
              ValueName = 'PreventIgnoreCertErrors'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Warn about bad certificate receiving
         RegistryPolicyFile 'WarnOnBadCertRecving'
         {
              ValueName = 'WarnOnBadCertRecving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Disable SSL 3.0 fallback (security hardening)
         RegistryPolicyFile 'EnableSSL3Fallback'
         {
              ValueName = 'EnableSSL3Fallback'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Configure secure protocols (TLS 1.1 and TLS 1.2 enabled)
         RegistryPolicyFile 'SecureProtocols'
         {
              ValueName = 'SecureProtocols'
              ValueData = 2560
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         # Disable automatic prompting for ActiveX controls in Lockdown My Computer Zone
         RegistryPolicyFile 'LockdownZone0_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
         }

         # Disable automatic prompting for ActiveX controls in Lockdown Local Intranet Zone
         RegistryPolicyFile 'LockdownZone1_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
         }

         # Disable automatic prompting for ActiveX controls in Lockdown Trusted Sites Zone
         RegistryPolicyFile 'LockdownZone2_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
         }

         # Disable drag and drop or copy/paste files in Lockdown Internet Zone
         RegistryPolicyFile 'LockdownZone3_DragDrop'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3'
         }

         # Disable drag and drop or copy/paste files in Lockdown Restricted Sites Zone
         RegistryPolicyFile 'LockdownZone4_DragDrop'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
         }

         # Disable automatic prompting for ActiveX controls in Lockdown Restricted Sites Zone
         RegistryPolicyFile 'LockdownZone4_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
         }

         # Do not treat UNC paths as Intranet sites (security hardening)
         RegistryPolicyFile 'UNCAsIntranet'
         {
              ValueName = 'UNCAsIntranet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
         }

         # Disable automatic prompting for ActiveX controls in My Computer Zone
         RegistryPolicyFile 'Zone0_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
         }

         # Disable reserved control block actions in My Computer Zone
         RegistryPolicyFile 'Zone0_ReservedControl'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
         }

         # Disable reserved control block actions in Local Intranet Zone
         RegistryPolicyFile 'Zone1_ReservedControl'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         # Prompt before downloading unsigned ActiveX controls in Local Intranet Zone
         RegistryPolicyFile 'Zone1_UnsignedActiveX'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         # Configure automatic prompting for ActiveX controls in Local Intranet Zone
         RegistryPolicyFile 'Zone1_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         # Configure automatic prompting for ActiveX controls in Trusted Sites Zone
         RegistryPolicyFile 'Zone2_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         # Disable reserved control block actions in Trusted Sites Zone
         RegistryPolicyFile 'Zone2_ReservedControl'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         # Prompt before downloading unsigned ActiveX controls in Trusted Sites Zone
         RegistryPolicyFile 'Zone2_UnsignedActiveX'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         # Prompt before allowing websites to open windows without address bars in Internet Zone
         RegistryPolicyFile 'Zone3_WindowsWithoutBars'
         {
              ValueName = '2001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing access to data sources across domains in Internet Zone
         RegistryPolicyFile 'Zone3_CrossDomainData'
         {
              ValueName = '2102'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing drag content from different domains within a window in Internet Zone
         RegistryPolicyFile 'Zone3_DragDropWithinWindow'
         {
              ValueName = '1802'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing drag content from different domains across windows in Internet Zone
         RegistryPolicyFile 'Zone3_DragDropAcrossWindows'
         {
              ValueName = '160A'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before downloading unsigned ActiveX controls in Internet Zone
         RegistryPolicyFile 'Zone3_UnsignedActiveX'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing automatic downloading of files in Internet Zone
         RegistryPolicyFile 'Zone3_AutoDownload'
         {
              ValueName = '1406'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing font downloads in Internet Zone
         RegistryPolicyFile 'Zone3_FontDownload'
         {
              ValueName = '1804'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing automatic prompting for file downloads in Internet Zone
         RegistryPolicyFile 'Zone3_FileDownloadPrompt'
         {
              ValueName = '2200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing Java permissions in Internet Zone
         RegistryPolicyFile 'Zone3_JavaPermissions'
         {
              ValueName = '1209'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before launching applications and unsafe files in Internet Zone
         RegistryPolicyFile 'Zone3_LaunchUnsafeFiles'
         {
              ValueName = '1206'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Disable use of Popup Blocker in Internet Zone
         RegistryPolicyFile 'Zone3_PopupBlocker'
         {
              ValueName = '1809'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Disable Protected Mode in Internet Zone
         RegistryPolicyFile 'Zone3_ProtectedMode'
         {
              ValueName = '2500'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing access to data sources across domains in Internet Zone  
         RegistryPolicyFile 'Zone3_IncludeLocalPath'
         {
              ValueName = '2103'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing scriptlets in Internet Zone
         RegistryPolicyFile 'Zone3_Scriptlets'
         {
              ValueName = '1606'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing META REFRESH in Internet Zone
         RegistryPolicyFile 'Zone3_MetaRefresh'
         {
              ValueName = '2402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing programmatic clipboard access in Internet Zone
         RegistryPolicyFile 'Zone3_ClipboardAccess'
         {
              ValueName = '2004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Disable automatic prompting for ActiveX controls in Internet Zone
         RegistryPolicyFile 'Zone3_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before downloading signed ActiveX controls in Internet Zone
         RegistryPolicyFile 'Zone3_SignedActiveX'
         {
              ValueName = '1001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Configure logon options in Internet Zone (automatic logon with current credentials)
         RegistryPolicyFile 'Zone3_LogonOptions'
         {
              ValueName = '1A00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing VBScript to run in Internet Zone
         RegistryPolicyFile 'Zone3_VBScript'
         {
              ValueName = '2708'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing downloads in Internet Zone
         RegistryPolicyFile 'Zone3_FileDownload'
         {
              ValueName = '1004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing Scripting of Java applets in Internet Zone
         RegistryPolicyFile 'Zone3_JavaScripting'
         {
              ValueName = '120b'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before running .NET Framework reliant components not signed with Authenticode in Internet Zone
         RegistryPolicyFile 'Zone3_DotNetUnsigned'
         {
              ValueName = '1407'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Disable automatic prompting for file downloads in Internet Zone
         RegistryPolicyFile 'Zone3_AutoFileDownload'
         {
              ValueName = '1409'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Disable reserved control block actions in Internet Zone
         RegistryPolicyFile 'Zone3_ReservedControl'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing scripting of Internet Explorer WebBrowser control in Internet Zone
         RegistryPolicyFile 'Zone3_WebBrowserScripting'
         {
              ValueName = '1607'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing VBScript to access ActiveX controls in Internet Zone
         RegistryPolicyFile 'Zone3_VBScriptActiveX'
         {
              ValueName = '2709'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing Active Scripting in Internet Zone
         RegistryPolicyFile 'Zone3_ActiveScripting'
         {
              ValueName = '2101'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Disable drag and drop or copy/paste files in Internet Zone
         RegistryPolicyFile 'Zone3_DragDrop'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing binary and script behaviors in Internet Zone
         RegistryPolicyFile 'Zone3_BinaryScriptBehaviors'
         {
              ValueName = '1806'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing .NET Framework reliant components signed with Authenticode in Internet Zone
         RegistryPolicyFile 'Zone3_DotNetSigned'
         {
              ValueName = '120c'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before running .NET Framework reliant components signed with Authenticode in Internet Zone
         RegistryPolicyFile 'Zone3_DotNetSignedRun'
         {
              ValueName = '140C'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         # Prompt before allowing websites to use the XMLHTTP object in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_XMLHTTP'
         {
              ValueName = '1608'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before downloading unsigned ActiveX controls in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_UnsignedActiveX'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before downloading signed ActiveX controls in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_SignedActiveX'
         {
              ValueName = '1001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing scripting of Internet Explorer WebBrowser control in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_WebBrowserScripting'
         {
              ValueName = '1607'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing Scripting of Java applets in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_JavaScripting'
         {
              ValueName = '120b'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Disable use of Popup Blocker in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_PopupBlocker'
         {
              ValueName = '1809'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing downloads in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_FileDownload'
         {
              ValueName = '1004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing scriptlets in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_Scriptlets'
         {
              ValueName = '1606'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before running .NET Framework reliant components not signed with Authenticode in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_DotNetUnsigned'
         {
              ValueName = '1407'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing drag content from different domains across windows in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_DragDropAcrossWindows'
         {
              ValueName = '160A'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing automatic downloading of files in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_AutoDownload'
         {
              ValueName = '1406'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing access to data sources across domains in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_CrossDomainData'
         {
              ValueName = '2102'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing programmatic clipboard access in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_ClipboardAccess'
         {
              ValueName = '2004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing automatic prompting for file downloads in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_FileDownloadPrompt'
         {
              ValueName = '2200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing pop-up windows in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_PopupWindows'
         {
              ValueName = '2000'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before initializing and scripting ActiveX controls not marked safe in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_UnsafeActiveX'
         {
              ValueName = '1402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before submitting unencrypted form data in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_UnencryptedForms'
         {
              ValueName = '1803'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing META REFRESH in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_MetaRefresh'
         {
              ValueName = '2402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before running ActiveX controls and plugins in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_RunActiveX'
         {
              ValueName = '1400'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Configure logon options in Restricted Sites Zone (anonymous logon)
         RegistryPolicyFile 'Zone4_LogonOptions'
         {
              ValueName = '1A00'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing websites to open windows without address bars in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_WindowsWithoutBars'
         {
              ValueName = '2001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Disable Protected Mode in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_ProtectedMode'
         {
              ValueName = '2500'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Disable automatic prompting for file downloads in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_AutoFileDownload'
         {
              ValueName = '1409'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Disable automatic prompting for ActiveX controls in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_AutoPrompt'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing Java permissions in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_JavaPermissions'
         {
              ValueName = '1209'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Disable reserved control block actions in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_ReservedControl'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before launching applications and unsafe files in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_LaunchUnsafeFiles'
         {
              ValueName = '1206'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing VBScript to run in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_VBScript'
         {
              ValueName = '2708'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing drag content from different domains within a window in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_DragDropWithinWindow'
         {
              ValueName = '1802'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing access to data sources across domains in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_IncludeLocalPath'
         {
              ValueName = '2103'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing VBScript to access ActiveX controls in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_VBScriptActiveX'
         {
              ValueName = '2709'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before scripting ActiveX controls marked safe for scripting in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_SafeActiveXScripting'
         {
              ValueName = '1405'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing Active Scripting in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_ActiveScripting'
         {
              ValueName = '2101'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Disable drag and drop or copy/paste files in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_DragDrop'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing Run ActiveX controls and plugins in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_RunActiveXControls'
         {
              ValueName = '1200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing font downloads in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_FontDownload'
         {
              ValueName = '1804'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing binary and script behaviors in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_BinaryScriptBehaviors'
         {
              ValueName = '1806'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before allowing .NET Framework reliant components signed with Authenticode in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_DotNetSigned'
         {
              ValueName = '120c'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         # Prompt before running .NET Framework reliant components signed with Authenticode in Restricted Sites Zone
         RegistryPolicyFile 'Zone4_DotNetSignedRun'
         {
              ValueName = '140C'
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

	Node 'MSFT_InternetExplorer11_Computer'
	{
         # Disable "Run this time" for outdated ActiveX controls to prevent security risks
         RegistryPolicyFile 'RunThisTimeEnabled'
         {
              ValueName = 'RunThisTimeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
         }

         # Enable version checking for ActiveX controls to ensure up-to-date security
         RegistryPolicyFile 'VersionCheckEnabled'
         {
              ValueName = 'VersionCheckEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
         }

         # Block execution of files with invalid digital signatures from downloads
         RegistryPolicyFile 'RunInvalidSignatures'
         {
              ValueName = 'RunInvalidSignatures'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
         }

         # Require signature verification for executable downloads
         RegistryPolicyFile 'CheckExeSignatures'
         {
              ValueName = 'CheckExeSignatures'
              ValueData = 'yes'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
         }

         # Enable 64-bit Enhanced Protected Mode for better security isolation
         RegistryPolicyFile 'Isolation64Bit'
         {
              ValueName = 'Isolation64Bit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         # Disable Enhanced Protected Mode compatibility mode
         RegistryPolicyFile 'DisableEPMCompat'
         {
              ValueName = 'DisableEPMCompat'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         # Set process isolation to Protected Mode Enhanced Memory (PMEM)
         RegistryPolicyFile 'Isolation'
         {
              ValueName = 'Isolation'
              ValueData = 'PMEM'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

         # Disable MK protocol support for Reserved applications (security risk)
         RegistryPolicyFile 'DisableMkProtocol_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         # Disable MK protocol support for Internet Explorer process
         RegistryPolicyFile 'DisableMkProtocol_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         # Disable MK protocol support for Windows Explorer process
         RegistryPolicyFile 'DisableMkProtocol_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
         }

         # Enable consistent MIME handling for Windows Explorer
         RegistryPolicyFile 'MimeHandling_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         # Enable consistent MIME handling for Internet Explorer
         RegistryPolicyFile 'MimeHandling_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         # Enable consistent MIME handling for Reserved applications
         RegistryPolicyFile 'MimeHandling_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
         }

         # Disable MIME sniffing for Windows Explorer (security hardening)
         RegistryPolicyFile 'DisableMimeSniffing_Explorer'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         # Disable MIME sniffing for Internet Explorer (security hardening)
         RegistryPolicyFile 'DisableMimeSniffing_IExplore'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         # Disable MIME sniffing for Reserved applications (security hardening)
         RegistryPolicyFile 'DisableMimeSniffing_Reserved'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
         {
              ValueName = '(Reserved)'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
         {
              ValueName = 'explorer.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
         {
              ValueName = 'iexplore.exe'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
         {
              ValueName = 'PreventOverrideAppRepUnknown'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
         {
              ValueName = 'PreventOverride'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
         {
              ValueName = 'EnabledV9'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
         {
              ValueName = 'NoCrashDetection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
         {
              ValueName = 'DisableSecuritySettingsCheck'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
         {
              ValueName = 'BlockNonAdminActiveXInstall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AxInstaller\OnlyUseAXISForActiveXInstall'
         {
              ValueName = 'OnlyUseAXISForActiveXInstall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\AxInstaller'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
         {
              ValueName = 'Security_zones_map_edit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
         {
              ValueName = 'Security_options_edit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
         {
              ValueName = 'Security_HKLM_only'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\CertificateRevocation'
         {
              ValueName = 'CertificateRevocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors'
         {
              ValueName = 'PreventIgnoreCertErrors'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WarnOnBadCertRecving'
         {
              ValueName = 'WarnOnBadCertRecving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\EnableSSL3Fallback'
         {
              ValueName = 'EnableSSL3Fallback'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols'
         {
              ValueName = 'SecureProtocols'
              ValueData = 2560
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3\2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
         {
              ValueName = 'UNCAsIntranet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
         {
              ValueName = '1C00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
         {
              ValueName = '1C00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
         {
              ValueName = '2001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
         {
              ValueName = '2102'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
         {
              ValueName = '1802'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
         {
              ValueName = '160A'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
         {
              ValueName = '1406'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
         {
              ValueName = '1804'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
         {
              ValueName = '2200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
         {
              ValueName = '1209'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
         {
              ValueName = '1206'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
         {
              ValueName = '1809'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
         {
              ValueName = '2500'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
         {
              ValueName = '2103'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
         {
              ValueName = '1606'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
         {
              ValueName = '2402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
         {
              ValueName = '2004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
         {
              ValueName = '1001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
         {
              ValueName = '1A00'
              ValueData = 65536
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
         {
              ValueName = '2708'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
         {
              ValueName = '1004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
         {
              ValueName = '120b'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
         {
              ValueName = '1407'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
         {
              ValueName = '1409'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
         {
              ValueName = '1607'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
         {
              ValueName = '2709'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
         {
              ValueName = '2101'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
         {
              ValueName = '1806'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
         {
              ValueName = '120c'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
         {
              ValueName = '140C'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
         {
              ValueName = '1608'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
         {
              ValueName = '1201'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
         {
              ValueName = '1001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
         {
              ValueName = '1607'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
         {
              ValueName = '120b'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
         {
              ValueName = '1809'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
         {
              ValueName = '1004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
         {
              ValueName = '1606'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
         {
              ValueName = '1407'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
         {
              ValueName = '160A'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
         {
              ValueName = '1406'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
         {
              ValueName = '2102'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
         {
              ValueName = '2004'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
         {
              ValueName = '2200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
         {
              ValueName = '2000'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
         {
              ValueName = '1402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
         {
              ValueName = '1803'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
         {
              ValueName = '2402'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
         {
              ValueName = '1400'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
         {
              ValueName = '1A00'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
         {
              ValueName = '2001'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
         {
              ValueName = '2500'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
         {
              ValueName = '1409'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
         {
              ValueName = '1C00'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
         {
              ValueName = '1209'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
         {
              ValueName = '270C'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
         {
              ValueName = '1206'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
         {
              ValueName = '2708'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
         {
              ValueName = '1802'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
         {
              ValueName = '2103'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
         {
              ValueName = '2709'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
         {
              ValueName = '1405'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
         {
              ValueName = '2101'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
         {
              ValueName = '2301'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
         {
              ValueName = '1200'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
         {
              ValueName = '1804'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
         {
              ValueName = '1806'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
         {
              ValueName = '120c'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
         {
              ValueName = '140C'
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
