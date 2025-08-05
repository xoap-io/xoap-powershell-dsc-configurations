
Configuration 'MSTF_SecurityBaseline_W11_Computer'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_Computer'
     {

        # --- Computer Configuration Registry Policies ---

        # Prevents automatic connection to OEM Wi-Fi networks for security
        RegistryPolicyFile 'config'
        {
            ValueName  = 'AutoConnectAllowedOEM'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config'
        }

        # Hides administrator accounts from the login UI for privacy
        RegistryPolicyFile 'CredUI'
        {
            ValueName  = 'EnumerateAdministrators'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
        }

        # Disables AutoRun on all drive types to prevent malware spread
        RegistryPolicyFile 'Explorer'
        {
            ValueName  = 'NoDriveTypeAutoRun'
            ValueData  = 255
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

        # Disables web services in Explorer for privacy and security
        RegistryPolicyFile 'Explorer_NoWebServices'
        {
            ValueName  = 'NoWebServices'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        }

         RegistryPolicyFile 'Explorer_NoAutorun'
         {
            # Disables AutoRun globally for all drives
              ValueName = 'NoAutorun'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

     # Makes Microsoft account optional for device sign-in
         RegistryPolicyFile 'System'
         {
              ValueName = 'MSAOptional'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         # Disables automatic restart and sign-on after updates
         RegistryPolicyFile 'System'
         {
              ValueName = 'DisableAutomaticRestartSignOn'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         # Prevents local accounts from bypassing token filtering for remote access
         RegistryPolicyFile 'System'
         {
              ValueName = 'LocalAccountTokenFilterPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         # Disallows weak CredSSP encryption oracle fallback
         RegistryPolicyFile 'Parameters'
         {
              ValueName = 'AllowEncryptionOracle'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
         }

         # Enables enhanced anti-spoofing for Windows Hello facial recognition
         RegistryPolicyFile 'FacialFeatures'
         {
              ValueName = 'EnhancedAntiSpoofing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
         }

         RegistryPolicyFile 'Feeds'
         {
            # Disables automatic download of feed enclosures in IE
              ValueName = 'DisableEnclosureDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
         }

         RegistryPolicyFile 'PowerSettings_DCSettingIndex'
         {
            # Sets power management for sleep settings on battery (DC)
              ValueName = 'DCSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
         }

         RegistryPolicyFile 'PowerSettings_ACSettingIndex'
         {
            # Sets power management for sleep settings on AC power
              ValueName = 'ACSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
         }

         RegistryPolicyFile 'AppPrivacy_LetAppsActivateWithVoiceAboveLock'
         {
            # Restricts apps from activating with voice above lock screen
              ValueName = 'LetAppsActivateWithVoiceAboveLock'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy'
         }

         RegistryPolicyFile 'CloudContent'
         {
            # Disables Windows consumer features (ads, suggestions)
              ValueName = 'DisableWindowsConsumerFeatures'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
         }

         RegistryPolicyFile 'CredentialsDelegation'
         {
            # Allows delegation of protected credentials for remote desktop
              ValueName = 'AllowProtectedCreds'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
         }

         # Sets maximum size for Application event log
         RegistryPolicyFile 'Application'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
         }

         # Sets maximum size for Security event log
         RegistryPolicyFile 'Security'
         {
              ValueName = 'MaxSize'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
         }

         # Sets maximum size for System event log
         RegistryPolicyFile 'System'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
         }

         # Disables autoplay for non-volume devices
         RegistryPolicyFile 'Explorer_NoAutoplayfornonVolume'
         {
              ValueName = 'NoAutoplayfornonVolume'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         # Disables Game DVR feature for privacy and performance
         RegistryPolicyFile 'GameDVR_AllowGameDVR'
         {
              ValueName = 'AllowGameDVR'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\GameDVR'
         }

         RegistryPolicyFile 'GroupPolicy_NoGPOListChanges'
         {
            # Allows GPO list changes for group policy processing
              ValueName = 'NoGPOListChanges'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'GroupPolicy_NoBackgroundPolicy'
         {
            # Allows background policy processing for group policy
              ValueName = 'NoBackgroundPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'Installer_AlwaysInstallElevated'
         {
            # Prevents elevated installs for non-admin users
              ValueName = 'AlwaysInstallElevated'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Installer_EnableUserControl'
         {
            # Disables user control over Windows Installer
              ValueName = 'EnableUserControl'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'KernelDMAProtection_DeviceEnumerationPolicy'
         {
            # Restricts device enumeration for DMA protection
              ValueName = 'DeviceEnumerationPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
         }

         RegistryPolicyFile 'LanmanWorkstation_AllowInsecureGuestAuth'
         {
            # Disables insecure guest authentication for SMB
              ValueName = 'AllowInsecureGuestAuth'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
         }

         RegistryPolicyFile 'NetworkConnections_NC_ShowSharedAccessUI'
         {
            # Hides shared access UI for network connections
              ValueName = 'NC_ShowSharedAccessUI'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections'
         }

         RegistryPolicyFile 'HardenedPaths_SYSVOL'
         {
            # Requires mutual authentication and integrity for SYSVOL access
              ValueName = '\\*\SYSVOL'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
         }

         RegistryPolicyFile 'HardenedPaths_NETLOGON'
         {
            # Requires mutual authentication and integrity for NETLOGON access
              ValueName = '\\*\NETLOGON'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
         }

         RegistryPolicyFile 'Personalization_NoLockScreenCamera'
         {
            # Disables camera on lock screen for privacy
              ValueName = 'NoLockScreenCamera'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'Personalization_NoLockScreenSlideshow'
         {
            # Disables lock screen slideshow for privacy
              ValueName = 'NoLockScreenSlideshow'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'ScriptBlockLogging_EnableScriptBlockLogging'
         {
            # Enables PowerShell script block logging for auditing
              ValueName = 'EnableScriptBlockLogging'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'ScriptBlockLogging_EnableScriptBlockInvocationLogging'
         {
            # Removes invocation logging for PowerShell script blocks
              ValueName = 'EnableScriptBlockInvocationLogging'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'System_AllowDomainPINLogon'
         {
            # Disables domain PIN logon for increased security
              ValueName = 'AllowDomainPINLogon'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'System_EnumerateLocalUsers'
         {
            # Prevents enumeration of local users for privacy
              ValueName = 'EnumerateLocalUsers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'System_EnableSmartScreen'
         {
            # Enables Windows SmartScreen for protection against malicious content
              ValueName = 'EnableSmartScreen'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'System_ShellSmartScreenLevel'
         {
            # Sets SmartScreen level to block unrecognized apps
              ValueName = 'ShellSmartScreenLevel'
              ValueData = 'Block'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'GroupPolicy_fBlockNonDomain'
         {
            # Blocks non-domain devices from connecting to Wi-Fi
              ValueName = 'fBlockNonDomain'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
         }

         RegistryPolicyFile 'WindowsSearch_AllowIndexingEncryptedStoresOrItems'
         {
            # Prevents indexing of encrypted stores/items for privacy
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'WinRMClient_AllowDigest'
         {
            # Disables Digest authentication for WinRM client
              ValueName = 'AllowDigest'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'WinRMClient_AllowUnencryptedTraffic'
         {
            # Disables unencrypted traffic for WinRM client
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'WinRMClient_AllowBasic'
         {
            # Disables Basic authentication for WinRM client
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'WinRMService_AllowUnencryptedTraffic'
         {
            # Disables unencrypted traffic for WinRM service
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'WinRMService_DisableRunAs'
         {
            # Disables RunAs for WinRM service
              ValueName = 'DisableRunAs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'WinRMService_AllowBasic'
         {
            # Disables Basic authentication for WinRM service
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'DNSClient_EnableMulticast'
         {
            # Disables multicast name resolution for DNS client
              ValueName = 'EnableMulticast'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
         }

         RegistryPolicyFile 'Printers_DisableWebPnPDownload'
         {
            # Disables WebPnP printer driver download
              ValueName = 'DisableWebPnPDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
         }

         RegistryPolicyFile 'PointAndPrint_RestrictDriverInstallationToAdministrators'
         {
            # Restricts printer driver installation to administrators only
              ValueName = 'RestrictDriverInstallationToAdministrators'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
         }

         RegistryPolicyFile 'Rpc_RestrictRemoteClients'
         {
            # Restricts remote RPC clients for security
              ValueName = 'RestrictRemoteClients'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc'
         }

         RegistryPolicyFile 'TerminalServices_fUseMailto'
         {
            # Removes mailto support in Terminal Services
              ValueName = 'fUseMailto'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_fAllowToGetHelp'
         {
            # Disables remote assistance in Terminal Services
              ValueName = 'fAllowToGetHelp'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_fAllowFullControl'
         {
            # Removes full control permission in Terminal Services
              ValueName = 'fAllowFullControl'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_MaxTicketExpiry'
         {
            # Removes max ticket expiry setting in Terminal Services
              ValueName = 'MaxTicketExpiry'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_MaxTicketExpiryUnits'
         {
            # Removes max ticket expiry units setting in Terminal Services
              ValueName = 'MaxTicketExpiryUnits'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_MinEncryptionLevel'
         {
            # Sets minimum encryption level for Terminal Services
              ValueName = 'MinEncryptionLevel'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_fPromptForPassword'
         {
            # Prompts for password in Terminal Services sessions
              ValueName = 'fPromptForPassword'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_fDisableCdm'
         {
            # Disables client drive mapping in Terminal Services
              ValueName = 'fDisableCdm'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_DisablePasswordSaving'
         {
            # Disables password saving in Terminal Services
              ValueName = 'DisablePasswordSaving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'TerminalServices_fEncryptRPCTraffic'
         {
            # Encrypts RPC traffic in Terminal Services
              ValueName = 'fEncryptRPCTraffic'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'WindowsFirewall_PolicyVersion'
         {
            # Sets Windows Firewall policy version
              ValueName = 'PolicyVersion'
              ValueData = 538
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
         }

         RegistryPolicyFile 'DomainProfile_DefaultOutboundAction'
         {
            # Sets default outbound action for domain firewall profile
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'DomainProfile_DisableNotifications'
         {
            # Disables notifications for domain firewall profile
              ValueName = 'DisableNotifications'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'DomainProfile_EnableFirewall'
         {
            # Enables firewall for domain profile
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'DomainProfile_DefaultInboundAction'
         {
            # Sets default inbound action for domain firewall profile
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'DomainProfileLogging_LogDroppedPackets'
         {
            # Enables logging of dropped packets for domain firewall profile
              ValueName = 'LogDroppedPackets'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
         }

         RegistryPolicyFile 'DomainProfileLogging_LogFileSize'
         {
            # Sets log file size for domain firewall profile
              ValueName = 'LogFileSize'
              ValueData = 16384
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
         }

         RegistryPolicyFile 'DomainProfileLogging_LogSuccessfulConnections'
         {
            # Enables logging of successful connections for domain firewall profile
              ValueName = 'LogSuccessfulConnections'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
         }

         RegistryPolicyFile 'PrivateProfile_EnableFirewall'
         {
            # Enables firewall for private profile
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'PrivateProfile_DisableNotifications'
         {
            # Disables notifications for private firewall profile
              ValueName = 'DisableNotifications'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'PrivateProfile_DefaultInboundAction'
         {
            # Sets default inbound action for private firewall profile
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'PrivateProfile_DefaultOutboundAction'
         {
            # Sets default outbound action for private firewall profile
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'PrivateProfileLogging_LogSuccessfulConnections'
         {
            # Enables logging of successful connections for private firewall profile
              ValueName = 'LogSuccessfulConnections'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
         }

         RegistryPolicyFile 'PrivateProfileLogging_LogDroppedPackets'
         {
            # Enables logging of dropped packets for private firewall profile
              ValueName = 'LogDroppedPackets'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
         }

         RegistryPolicyFile 'PrivateProfileLogging_LogFileSize'
         {
            # Sets log file size for private firewall profile
              ValueName = 'LogFileSize'
              ValueData = 16384
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
         }

         RegistryPolicyFile 'PublicProfile_DefaultOutboundAction'
         {
            # Sets default outbound action for public firewall profile
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'PublicProfile_EnableFirewall'
         {
            # Enables firewall for public profile
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'PublicProfile_DisableNotifications'
         {
            # Disables notifications for public firewall profile
              ValueName = 'DisableNotifications'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'PublicProfile_AllowLocalIPsecPolicyMerge'
         {
            # Disables merging of local IPsec policies for public profile
              ValueName = 'AllowLocalIPsecPolicyMerge'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'PublicProfile_AllowLocalPolicyMerge'
         {
            # Disables merging of local policies for public profile
              ValueName = 'AllowLocalPolicyMerge'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'PublicProfile_DefaultInboundAction'
         {
            # Sets default inbound action for public firewall profile
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'PublicProfileLogging_LogFileSize'
         {
            # Sets log file size for public firewall profile
              ValueName = 'LogFileSize'
              ValueData = 16384
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
         }

         RegistryPolicyFile 'PublicProfileLogging_LogDroppedPackets'
         {
            # Enables logging of dropped packets for public firewall profile
              ValueName = 'LogDroppedPackets'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
         }

         RegistryPolicyFile 'PublicProfileLogging_LogSuccessfulConnections'
         {
            # Enables logging of successful connections for public firewall profile
              ValueName = 'LogSuccessfulConnections'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
         }

         RegistryPolicyFile 'WindowsInkWorkspace_AllowWindowsInkWorkspace'
         {
            # Enables Windows Ink Workspace feature
              ValueName = 'AllowWindowsInkWorkspace'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
         }

         RegistryPolicyFile 'AdmPwd_AdmPwdEnabled'
         {
            # Enables LAPS (Local Administrator Password Solution)
              ValueName = 'AdmPwdEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
         }

         RegistryPolicyFile 'WDigest_UseLogonCredential'
         {
            # Prevents storing logon credentials for WDigest authentication
              ValueName = 'UseLogonCredential'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
         }

         RegistryPolicyFile 'kernel_DisableExceptionChainValidation'
         {
            # Enables exception chain validation for kernel security
              ValueName = 'DisableExceptionChainValidation'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
         }

         RegistryPolicyFile 'EarlyLaunch_DriverLoadPolicy'
         {
            # Sets driver load policy for early launch anti-malware
              ValueName = 'DriverLoadPolicy'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
         }

         RegistryPolicyFile 'LanmanServerParameters_SMB1'
         {
            # Disables SMBv1 protocol for security
              ValueName = 'SMB1'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
         }

         RegistryPolicyFile 'MrxSmb10_Start'
         {
            # Disables SMBv1 driver for security
              ValueName = 'Start'
              ValueData = 4
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
         }

         RegistryPolicyFile 'NetbtParameters_NoNameReleaseOnDemand'
         {
            # Prevents NetBIOS name release on demand
              ValueName = 'NoNameReleaseOnDemand'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
         }

         RegistryPolicyFile 'NetbtParameters_NodeType'
         {
            # Sets NetBIOS node type to hybrid for optimal name resolution
              ValueName = 'NodeType'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
         }

         RegistryPolicyFile 'TcpipParameters_EnableICMPRedirect'
         {
            # Disables ICMP redirect for TCP/IP
              ValueName = 'EnableICMPRedirect'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'TcpipParameters_DisableIPSourceRouting'
         {
            # Disables IP source routing for TCP/IP
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Tcpip6Parameters_DisableIPSourceRouting'
         {
            # Disables IP source routing for TCP/IPv6
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

         AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
         {
              Name = 'Security Group Management'
              Ensure = 'Absent'
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

         AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Absent'
              AuditFlag = 'Success'
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

         AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
         {
              Name = 'Other Logon/Logoff Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
         {
              Name = 'Other Logon/Logoff Events'
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

         AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
         {
              Name = 'Detailed File Share'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
         {
              Name = 'Detailed File Share'
              Ensure = 'Absent'
              AuditFlag = 'Success'
         }

         AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
         {
              Name = 'File Share'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
         {
              Name = 'File Share'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
         {
              Name = 'Other Object Access Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
         {
              Name = 'Other Object Access Events'
              Ensure = 'Present'
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
              Ensure = 'Absent'
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

         AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
         {
              Name = 'MPSSVC Rule-Level Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
         {
              Name = 'MPSSVC Rule-Level Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
         {
              Name = 'Other Policy Change Events'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

          AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
         {
              Name = 'Other Policy Change Events'
              Ensure = 'Absent'
              AuditFlag = 'Success'
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
              Ensure = 'Absent'
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

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Force = $True
              Identity = @('*S-1-5-113')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Policy = 'Back_up_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Policy = 'Lock_pages_in_memory'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Policy = 'Create_a_token_object'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Policy = 'Create_global_objects'
              Force = $True
              Identity = @('*S-1-5-32-544', '*S-1-5-6', '*S-1-5-19', '*S-1-5-20')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Policy = 'Restore_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-32-544', '*S-1-5-32-555')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
              Identity = @('*S-1-5-32-544', '*S-1-5-6', '*S-1-5-19', '*S-1-5-20')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Policy = 'Create_permanent_shared_objects'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-544', '*S-1-5-32-545')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-113')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
              Identity = @('')
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

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
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

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
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

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
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

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         Service 'Services(INF): XboxGipSvc'
         {
              Name = 'XboxGipSvc'
              State = 'Stopped'
         }

         Service 'Services(INF): XblAuthManager'
         {
              Name = 'XblAuthManager'
              State = 'Stopped'
         }

         Service 'Services(INF): XblGameSave'
         {
              Name = 'XblGameSave'
              State = 'Stopped'
         }

         Service 'Services(INF): XboxNetApiSvc'
         {
              Name = 'XboxNetApiSvc'
              State = 'Stopped'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
