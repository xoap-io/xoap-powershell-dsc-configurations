Configuration 'MSTF_SecurityBaseline_W11_22H2_IE11'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_22H2_IE11'
     {
        # Disables "Run this time" for extensions
        RegistryPolicyFile 'RunThisTimeEnabled'
        {
            ValueName = 'RunThisTimeEnabled'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
        }

        # Enables version check for extensions
        RegistryPolicyFile 'VersionCheckEnabled'
        {
            ValueName = 'VersionCheckEnabled'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
        }

        # Prevents running invalid signatures in IE downloads
        RegistryPolicyFile 'RunInvalidSignatures'
        {
            ValueName = 'RunInvalidSignatures'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
        }

        # Requires executable signatures in IE downloads
        RegistryPolicyFile 'CheckExeSignatures'
        {
            ValueName = 'CheckExeSignatures'
            ValueData = 'yes'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Download'
        }

        # Enables 64-bit tab isolation in IE
        RegistryPolicyFile 'Isolation64Bit'
         {
              ValueName = 'Isolation64Bit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

        # Disables Enhanced Protected Mode compatibility in IE
        RegistryPolicyFile 'DisableEPMCompat'
         {
              ValueName = 'DisableEPMCompat'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
         }

        # Enables tab isolation in IE
        RegistryPolicyFile 'Isolation'
        {
            ValueName = 'Isolation'
            ValueData = 'PMEM'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
        }

        # Enables MIME handling for explorer.exe
        RegistryPolicyFile 'explorer.exe'
        {
            ValueName = 'explorer.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
        }

        # Enables MIME sniffing for explorer.exe
        RegistryPolicyFile 'explorer.exe'
        {
            ValueName = 'explorer.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
        }


        # Enables MIME sniffing for iexplore.exe
        RegistryPolicyFile 'iexplore.exe'
        {
            ValueName = 'iexplore.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
        }

        # Restricts file downloads for iexplore.exe
        RegistryPolicyFile 'iexplore.exe'
        {
            ValueName = 'iexplore.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
        }

        # Restricts file downloads for explorer.exe
        RegistryPolicyFile 'explorer.exe'
        {
            ValueName = 'explorer.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
        }

        # Enables security band for (Reserved)
        RegistryPolicyFile '(Reserved)'
        {
            ValueName = '(Reserved)'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
        }

        # Enables security band for iexplore.exe
        RegistryPolicyFile 'iexplore.exe'
        {
            ValueName = 'iexplore.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
        }

        # Enables security band for explorer.exe
        RegistryPolicyFile 'explorer.exe'
        {
            ValueName = 'explorer.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
        }

        # Enables window restrictions for iexplore.exe
        RegistryPolicyFile 'iexplore.exe'
        {
            ValueName = 'iexplore.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
        }

        # Enables window restrictions for reserved value
        RegistryPolicyFile '(Reserved)'
        {
            ValueName = '(Reserved)'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
        }

        # Enables window restrictions for explorer.exe
        RegistryPolicyFile 'explorer.exe'
        {
            ValueName = 'explorer.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
        }

        # Enables zone elevation restrictions for reserved value
        RegistryPolicyFile '(Reserved)'
        {
            ValueName = '(Reserved)'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
        }

        # Enables zone elevation restrictions for explorer.exe
        RegistryPolicyFile 'explorer.exe'
        {
            ValueName = 'explorer.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
        }

        # Enables zone elevation restrictions for iexplore.exe
        RegistryPolicyFile 'iexplore.exe'
        {
            ValueName = 'iexplore.exe'
            ValueData = '1'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
        }

        # Prevents overriding application reputation unknown files warning
        RegistryPolicyFile 'PreventOverrideAppRepUnknown'
        {
            ValueName = 'PreventOverrideAppRepUnknown'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
        }

        # Prevents overriding phishing filter warnings
        RegistryPolicyFile 'PreventOverride'
        {
            ValueName = 'PreventOverride'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
        }

        # Enables phishing filter version 9
        RegistryPolicyFile 'EnabledV9'
        {
            ValueName = 'EnabledV9'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
        }

        # Disables IE crash detection
        RegistryPolicyFile 'NoCrashDetection'
        {
            ValueName = 'NoCrashDetection'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions'
        }

        # Enables IE security settings check
        RegistryPolicyFile 'DisableSecuritySettingsCheck'
        {
            ValueName = 'DisableSecuritySettingsCheck'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security'
        }

        # Blocks non-admin ActiveX installation
        RegistryPolicyFile 'BlockNonAdminActiveXInstall'
        {
            ValueName = 'BlockNonAdminActiveXInstall'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
        }

        # Requires AXIS for ActiveX installation
        RegistryPolicyFile 'OnlyUseAXISForActiveXInstall'
        {
            ValueName = 'OnlyUseAXISForActiveXInstall'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\AxInstaller'
        }

        # Prevents editing security zone mappings
        RegistryPolicyFile 'Security_zones_map_edit'
        {
            ValueName = 'Security_zones_map_edit'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Prevents editing security options
        RegistryPolicyFile 'Security_options_edit'
        {
            ValueName = 'Security_options_edit'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Forces security settings from HKLM only
        RegistryPolicyFile 'Security_HKLM_only'
        {
            ValueName = 'Security_HKLM_only'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Enables certificate revocation checking
        RegistryPolicyFile 'CertificateRevocation'
        {
            ValueName = 'CertificateRevocation'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Prevents ignoring certificate errors
        RegistryPolicyFile 'PreventIgnoreCertErrors'
        {
            ValueName = 'PreventIgnoreCertErrors'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Enables certificate receiving warnings
        RegistryPolicyFile 'WarnOnBadCertRecving'
        {
            ValueName = 'WarnOnBadCertRecving'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Disables SSL3 fallback
        RegistryPolicyFile 'EnableSSL3Fallback'
        {
            ValueName = 'EnableSSL3Fallback'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Sets secure protocols to TLS 1.1 and 1.2
        RegistryPolicyFile 'SecureProtocols'
        {
            ValueName = 'SecureProtocols'
            ValueData = 2560
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        # Disables automatic logon for My Computer zone (lockdown)
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
        }

        # Disables automatic logon for Local Intranet zone (lockdown)
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
        }

        # Disables automatic logon for Trusted Sites zone (lockdown)
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
        }

        # Disables smartscreen filter in Internet zone (lockdown)
        RegistryPolicyFile '2301'
        {
            ValueName = '2301'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3'
        }

        # Disables smartscreen filter in Restricted Sites zone (lockdown)
        RegistryPolicyFile '2301'
        {
            ValueName = '2301'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
        }

        # Disables automatic logon for Restricted Sites zone (lockdown)
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
        }

        # Disables treating UNC as Intranet
        RegistryPolicyFile 'UNCAsIntranet'
        {
            ValueName = 'UNCAsIntranet'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
        }

        # Disables automatic logon for My Computer zone
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
        }

        # Disables include local path when uploading files to server in My Computer zone
        RegistryPolicyFile '270C'
        {
            ValueName = '270C'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
        }

        # Disables include local path when uploading files to server in Local Intranet zone
        RegistryPolicyFile '270C'
        {
            ValueName = '270C'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
        }

        # Restricts file downloads in Local Intranet zone
        RegistryPolicyFile '1201'
        {
            ValueName = '1201'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
        }

        # Enables automatic logon with current user name and password in Local Intranet zone
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 65536
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
        }

        # Enables automatic logon with current user name and password in Trusted Sites zone
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 65536
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
        }

        # Disables include local path when uploading files to server in Trusted Sites zone
        RegistryPolicyFile '270C'
        {
            ValueName = '270C'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
        }

        # Restricts file downloads in Trusted Sites zone
        RegistryPolicyFile '1201'
        {
              ValueName = '1201'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
        }

        # Disables automatic prompting for file downloads in Internet zone
        RegistryPolicyFile '2001'
        {
            ValueName = '2001'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables .NET Framework reliant components in Internet zone
        RegistryPolicyFile '2102'
        {
            ValueName = '2102'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables drag and drop or copy/paste files in Internet zone
        RegistryPolicyFile '1802'
        {
            ValueName = '1802'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables .NET Framework reliant components that are not signed with authenticode in Internet zone
        RegistryPolicyFile '160A'
        {
            ValueName = '160A'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Restricts file downloads in Internet zone
        RegistryPolicyFile '1201'
        {
            ValueName = '1201'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables Font download in Internet zone
        RegistryPolicyFile '1406'
        {
            ValueName = '1406'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables file downloads in Internet zone
        RegistryPolicyFile '1804'
        {
            ValueName = '1804'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables UTF-8 URL encoding in Internet zone
        RegistryPolicyFile '2200'
        {
            ValueName = '2200'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables desktop items installation in Internet zone
        RegistryPolicyFile '1209'
        {
            ValueName = '1209'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables dragging of content from different domains within a window in Internet zone
        RegistryPolicyFile '1206'
        {
            ValueName = '1206'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables accessing data sources across domains in Internet zone
        RegistryPolicyFile '1809'
        {
            ValueName = '1809'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables binary and script behaviors in Internet zone
        RegistryPolicyFile '2500'
        {
            ValueName = '2500'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables running of .NET Framework reliant components signed with authenticode in Internet zone
        RegistryPolicyFile '2103'
        {
            ValueName = '2103'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables scripting of windows opened programmatically without size/position constraints in Internet zone
        RegistryPolicyFile '1606'
        {
            ValueName = '1606'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables allow META REFRESH in Internet zone
        RegistryPolicyFile '2402'
        {
            ValueName = '2402'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables cross-site scripting filter in Internet zone
        RegistryPolicyFile '2004'
        {
            ValueName = '2004'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables automatic logon with current username and password in Internet zone
        RegistryPolicyFile '1C00'
        {
            ValueName = '1C00'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables downloading signed ActiveX controls in Internet zone
        RegistryPolicyFile '1001'
        {
            ValueName = '1001'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Enables User Authentication for logon in Internet zone
        RegistryPolicyFile '1A00'
        {
            ValueName = '1A00'
            ValueData = 65536
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables reserved navigation across domains from popup windows in Internet zone
        RegistryPolicyFile '2708'
        {
            ValueName = '2708'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables downloading unsigned ActiveX controls in Internet zone
        RegistryPolicyFile '1004'
        {
            ValueName = '1004'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables scripting in ActiveX controls marked safe for scripting in Internet zone
        RegistryPolicyFile '120b'
        {
            ValueName = '120b'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }       

        # Disables Active scripting in Internet zone
        RegistryPolicyFile '1409'
        {
            ValueName = '1409'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables include local path when uploading files to server in Internet zone
        RegistryPolicyFile '270C'
        {
            ValueName = '270C'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables navigate sub-frames across different domains in Internet zone
        RegistryPolicyFile '1607'
        {
            ValueName = '1607'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables open files based on content, not file extension in Internet zone
        RegistryPolicyFile '2709'
        {
            ValueName = '2709'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables .NET Framework reliant components that are unsigned in Internet zone
        RegistryPolicyFile '2101'
        {
            ValueName = '2101'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables smart screen filter in Internet zone
        RegistryPolicyFile '2301'
        {
            ValueName = '2301'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables pop-up blocker in Internet zone
        RegistryPolicyFile '1806'
        {
            ValueName = '1806'
            ValueData = 1
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables scripting in ActiveX controls marked safe for scripting in Internet zone
        RegistryPolicyFile '120c'
        {
            ValueName = '120c'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables automatic prompting for ActiveX controls in Internet zone
        RegistryPolicyFile '140C'
        {
            ValueName = '140C'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
        }

        # Disables use of WindowsAuthentication HTTP 401 in Restricted Sites zone
        RegistryPolicyFile '1608'
        {
            ValueName = '1608'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Restricts file downloads in Restricted Sites zone
        RegistryPolicyFile '1201'
        {
            ValueName = '1201'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables downloading signed ActiveX controls in Restricted Sites zone
        RegistryPolicyFile '1001'
        {
            ValueName = '1001'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables navigate sub-frames across different domains in Restricted Sites zone
        RegistryPolicyFile '1607'
        {
            ValueName = '1607'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables scripting in ActiveX controls marked safe for scripting in Restricted Sites zone
        RegistryPolicyFile '120b'
        {
            ValueName = '120b'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables accessing data sources across domains in Restricted Sites zone
        RegistryPolicyFile '1809'
        {
            ValueName = '1809'
            ValueData = 0
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables downloading unsigned ActiveX controls in Restricted Sites zone
        RegistryPolicyFile '1004'
        {
            ValueName = '1004'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables scripting of windows opened programmatically without size/position constraints in Restricted Sites zone
        RegistryPolicyFile '1606'
        {
            ValueName = '1606'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables ActiveX controls and plugins in Restricted Sites zone
        RegistryPolicyFile '1407'
        {
            ValueName = '1407'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Disables .NET Framework reliant components that are not signed with authenticode in Restricted Sites zone
        RegistryPolicyFile '160A'
        {
            ValueName = '160A'
            ValueData = 3
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        }

        # Refresh registry policy
        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
