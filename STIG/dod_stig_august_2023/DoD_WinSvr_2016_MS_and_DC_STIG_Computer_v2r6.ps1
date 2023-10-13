Configuration 'DoD_WinSvr_2016_MS_and_DC_STIG_Computer_v2r6'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
	
     Node 'DoD_WinSvr_2016_MS_and_DC_STIG_Computer_v2r6'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
              ValueType = 'Dword'
              ValueName = 'EnumerateAdministrators'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoAutorun'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 255
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoDriveTypeAutoRun'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueType = 'Dword'
              ValueName = 'DisableAutomaticRestartSignOn'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueType = 'Dword'
              ValueName = 'LocalAccountTokenFilterPolicy'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
              ValueType = 'Dword'
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
              ValueType = 'Dword'
              ValueName = 'DisableEnclosureDownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueType = 'Dword'
              ValueName = 'DCSettingIndex'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueType = 'Dword'
              ValueName = 'ACSettingIndex'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\AppCompat'
              ValueType = 'Dword'
              ValueName = 'DisableInventory'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DataCollection'
              ValueType = 'Dword'
              ValueName = 'AllowTelemetry'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'EnableVirtualizationBasedSecurity'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'RequirePlatformSecurityFeatures'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'HypervisorEnforcedCodeIntegrity'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'LsaCfgFlags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 32768
              Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
              ValueType = 'Dword'
              ValueName = 'MaxSize'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 196608
              Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
              ValueType = 'Dword'
              ValueName = 'MaxSize'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 32768
              Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
              ValueType = 'Dword'
              ValueName = 'MaxSize'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoAutoplayfornonVolume'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueType = 'Dword'
              ValueName = 'NoBackgroundPolicy'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueType = 'Dword'
              ValueName = 'NoGPOListChanges'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Installer'
              ValueType = 'Dword'
              ValueName = 'EnableUserControl'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Installer'
              ValueType = 'Dword'
              ValueName = 'AlwaysInstallElevated'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
              ValueType = 'Dword'
              ValueName = 'AllowInsecureGuestAuth'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueType = 'String'
              ValueName = '\\*\NETLOGON'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueType = 'String'
              ValueName = '\\*\SYSVOL'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\Personalization'
              ValueType = 'Dword'
              ValueName = 'NoLockScreenSlideshow'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueType = 'Dword'
              ValueName = 'EnableScriptBlockLogging'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'EnableScriptBlockInvocationLogging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\System'
              ValueType = 'Dword'
              ValueName = 'DontDisplayNetworkSelectionUI'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\System'
              ValueType = 'Dword'
              ValueName = 'EnumerateLocalUsers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\System'
              ValueType = 'Dword'
              ValueName = 'EnableSmartScreen'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Windows Search'
              ValueType = 'Dword'
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueType = 'Dword'
              ValueName = 'AllowBasic'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueType = 'Dword'
              ValueName = 'AllowUnencryptedTraffic'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueType = 'Dword'
              ValueName = 'AllowDigest'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueType = 'Dword'
              ValueName = 'AllowBasic'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueType = 'Dword'
              ValueName = 'AllowUnencryptedTraffic'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueType = 'Dword'
              ValueName = 'DisableRunAs'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Printers'
              ValueType = 'Dword'
              ValueName = 'DisableWebPnPDownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Printers'
              ValueType = 'Dword'
              ValueName = 'DisableHTTPPrinting'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'DisablePasswordSaving'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'fDisableCdm'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'fPromptForPassword'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'fEncryptRPCTraffic'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'MinEncryptionLevel'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
              ValueType = 'Dword'
              ValueName = 'UseLogonCredential'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
              ValueType = 'Dword'
              ValueName = 'SMB1'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 4
              Key = 'System\CurrentControlSet\Services\MrxSmb10'
              ValueType = 'Dword'
              ValueName = 'Start'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
              ValueType = 'Dword'
              ValueName = 'NoNameReleaseOnDemand'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
              ValueType = 'Dword'
              ValueName = 'DisableIPSourceRouting'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
              ValueType = 'Dword'
              ValueName = 'EnableICMPRedirect'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueType = 'Dword'
              ValueName = 'DisableIPSourceRouting'
         }

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
              ValueType = 'Dword'
              ValueName = 'EnumerateAdministrators'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoAutorun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 255
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoDriveTypeAutoRun'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueType = 'Dword'
              ValueName = 'DisableAutomaticRestartSignOn'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
              ValueType = 'Dword'
              ValueName = 'LocalAccountTokenFilterPolicy'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
              ValueType = 'Dword'
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
              ValueType = 'Dword'
              ValueName = 'DisableEnclosureDownload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueType = 'Dword'
              ValueName = 'DCSettingIndex'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
              ValueType = 'Dword'
              ValueName = 'ACSettingIndex'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\AppCompat'
              ValueType = 'Dword'
              ValueName = 'DisableInventory'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DataCollection'
              ValueType = 'Dword'
              ValueName = 'AllowTelemetry'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'EnableVirtualizationBasedSecurity'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'RequirePlatformSecurityFeatures'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'HypervisorEnforcedCodeIntegrity'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
              ValueType = 'Dword'
              ValueName = 'LsaCfgFlags'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 32768
              Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
              ValueType = 'Dword'
              ValueName = 'MaxSize'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 196608
              Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
              ValueType = 'Dword'
              ValueName = 'MaxSize'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 32768
              Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
              ValueType = 'Dword'
              ValueName = 'MaxSize'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoAutoplayfornonVolume'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueType = 'Dword'
              ValueName = 'NoBackgroundPolicy'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
              ValueType = 'Dword'
              ValueName = 'NoGPOListChanges'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Installer'
              ValueType = 'Dword'
              ValueName = 'EnableUserControl'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Installer'
              ValueType = 'Dword'
              ValueName = 'AlwaysInstallElevated'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
              ValueType = 'Dword'
              ValueName = 'AllowInsecureGuestAuth'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueType = 'String'
              ValueName = '\\*\NETLOGON'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
              ValueType = 'String'
              ValueName = '\\*\SYSVOL'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\Personalization'
              ValueType = 'Dword'
              ValueName = 'NoLockScreenSlideshow'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              ValueType = 'Dword'
              ValueName = 'EnableScriptBlockLogging'
         }#>

         <#RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'EnableScriptBlockInvocationLogging'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\System'
              ValueType = 'Dword'
              ValueName = 'DontDisplayNetworkSelectionUI'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\System'
              ValueType = 'Dword'
              ValueName = 'EnumerateLocalUsers'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\System'
              ValueType = 'Dword'
              ValueName = 'EnableSmartScreen'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\Windows Search'
              ValueType = 'Dword'
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueType = 'Dword'
              ValueName = 'AllowBasic'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueType = 'Dword'
              ValueName = 'AllowUnencryptedTraffic'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
              ValueType = 'Dword'
              ValueName = 'AllowDigest'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueType = 'Dword'
              ValueName = 'AllowBasic'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueType = 'Dword'
              ValueName = 'AllowUnencryptedTraffic'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
              ValueType = 'Dword'
              ValueName = 'DisableRunAs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Printers'
              ValueType = 'Dword'
              ValueName = 'DisableWebPnPDownload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Printers'
              ValueType = 'Dword'
              ValueName = 'DisableHTTPPrinting'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Rpc'
              ValueType = 'Dword'
              ValueName = 'RestrictRemoteClients'
         }

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'DisablePasswordSaving'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'fDisableCdm'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'fPromptForPassword'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'fEncryptRPCTraffic'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
              ValueType = 'Dword'
              ValueName = 'MinEncryptionLevel'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
              ValueType = 'Dword'
              ValueName = 'UseLogonCredential'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
              ValueType = 'Dword'
              ValueName = 'SMB1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 4
              Key = 'System\CurrentControlSet\Services\MrxSmb10'
              ValueType = 'Dword'
              ValueName = 'Start'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
              ValueType = 'Dword'
              ValueName = 'NoNameReleaseOnDemand'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
              ValueType = 'Dword'
              ValueName = 'DisableIPSourceRouting'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
              ValueType = 'Dword'
              ValueName = 'EnableICMPRedirect'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
              ValueType = 'Dword'
              ValueName = 'DisableIPSourceRouting'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoPreviewPane'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoReadingPane'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoReadingPane'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoReadingPane'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPreviewPane'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
              ValueType = 'Dword'
              ValueName = 'NoPreviewPane'
         }#>

         AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Credential Validation'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Credential Validation'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Computer Account Management'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Computer Account Management'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Other Account Management Events'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Other Account Management Events'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Security Group Management'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Security Group Management'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'User Account Management'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'User Account Management'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Plug and Play Events'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Plug and Play Events'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Process Creation'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Process Creation'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Directory Service Access'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Directory Service Access'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Directory Service Changes'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Directory Service Changes'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Account Lockout'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Account Lockout'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Group Membership'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Group Membership'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Logoff'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Logoff'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Logon'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Logon'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Special Logon'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Special Logon'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Other Object Access Events'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Other Object Access Events'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Removable Storage'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Removable Storage'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Audit Policy Change'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Audit Policy Change'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Authentication Policy Change'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Authentication Policy Change'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Authorization Policy Change'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Authorization Policy Change'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'IPsec Driver'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'IPsec Driver'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Other System Events'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Other System Events'
              Ensure = 'Present'
         }

         AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Security State Change'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Security State Change'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Security System Extension'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Security System Extension'
              Ensure = 'Absent'
         }

         AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'System Integrity'
              Ensure = 'Present'
         }

          AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'System Integrity'
              Ensure = 'Present'
         }

         <#AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Credential Validation'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Credential Validation'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Other Account Management Events'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Other Account Management Events'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Security Group Management'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Security Group Management'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'User Account Management'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'User Account Management'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Plug and Play Events'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Plug and Play Events'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Process Creation'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Process Creation'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Account Lockout'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Account Lockout'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Group Membership'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Group Membership'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Logoff'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Logoff'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Logon'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Logon'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Special Logon'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Special Logon'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Other Object Access Events'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Other Object Access Events'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Removable Storage'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Removable Storage'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Audit Policy Change'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Audit Policy Change'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Authentication Policy Change'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Authentication Policy Change'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Authorization Policy Change'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Authorization Policy Change'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Sensitive Privilege Use'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'IPsec Driver'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'IPsec Driver'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Other System Events'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Other System Events'
              Ensure = 'Present'
         }#>

         <#AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Security State Change'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Security State Change'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'Security System Extension'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'Security System Extension'
              Ensure = 'Absent'
         }#>

         <#AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
         {
              AuditFlag = 'Success'
              Name = 'System Integrity'
              Ensure = 'Present'
         }#>

          <#AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
         {
              AuditFlag = 'Failure'
              Name = 'System Integrity'
              Ensure = 'Present'
         }#>

         SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
         {
              Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
              System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
         {
              Name = 'Network_security_LAN_Manager_authentication_level'
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
         {
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         {
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         {
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
         {
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
         {
              Name = 'Interactive_logon_Machine_inactivity_limit'
              Interactive_logon_Machine_inactivity_limit = '900'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
         {
              Name = 'Domain_member_Disable_machine_account_password_changes'
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
         {
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Name = 'Domain_member_Maximum_machine_account_password_age'
              Domain_member_Maximum_machine_account_password_age = '30'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         {
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         {
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
         {
              Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
              Name = 'Domain_controller_Refuse_machine_account_password_changes'
         }

         SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         {
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
         {
              Name = 'Network_security_LDAP_client_signing_requirements'
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         {
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         {
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         {
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
         {
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
         {
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         {
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         {
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
         {
              Name = 'Domain_controller_LDAP_server_signing_requirements'
              Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
         {
              Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
              Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
         {
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         {
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
         {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
         {
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
         {
              Name = 'Interactive_logon_Smart_card_removal_behavior'
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         {
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         {
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         {
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         {
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Force = $True
              Policy = 'Act_as_part_of_the_operating_system'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Force = $True
              Policy = 'Take_ownership_of_files_or_other_objects'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Force = $True
              Policy = 'Manage_auditing_and_security_log'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
         {
              Force = $True
              Policy = 'Deny_log_on_as_a_batch_job'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Force = $True
              Policy = 'Load_and_unload_device_drivers'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Force = $True
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Force = $True
              Policy = 'Impersonate_a_client_after_authentication'
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Force = $True
              Policy = 'Increase_scheduling_priority'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Force = $True
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Force = $True
              Policy = 'Create_global_objects'
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Force = $True
              Policy = 'Force_shutdown_from_a_remote_system'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Force = $True
              Policy = 'Debug_programs'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Force = $True
              Policy = 'Create_permanent_shared_objects'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Force = $True
              Policy = 'Restore_files_and_directories'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Force = $True
              Policy = 'Access_this_computer_from_the_network'
              Identity = @('*S-1-5-32-544', '*S-1-5-11', '*S-1-5-9')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Force = $True
              Policy = 'Create_a_token_object'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Force = $True
              Policy = 'Generate_security_audits'
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Force = $True
              Policy = 'Allow_log_on_locally'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Force = $True
              Policy = 'Deny_log_on_locally'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Force = $True
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Force = $True
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Identity = @('*S-1-5-32-546')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Force = $True
              Policy = 'Perform_volume_maintenance_tasks'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Force = $True
              Policy = 'Modify_firmware_environment_values'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
         {
              Force = $True
              Policy = 'Allow_log_on_through_Remote_Desktop_Services'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Force = $True
              Policy = 'Create_symbolic_links'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Force = $True
              Policy = 'Back_up_files_and_directories'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
         {
              Force = $True
              Policy = 'Deny_log_on_as_a_service'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Force = $True
              Policy = 'Lock_pages_in_memory'
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
         {
              Force = $True
              Policy = 'Add_workstations_to_domain'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Force = $True
              Policy = 'Create_a_pagefile'
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Force = $True
              Policy = 'Profile_single_process'
              Identity = @('*S-1-5-32-544')
         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Store_passwords_using_reversible_encryption = 'Disabled'
              Name = 'Store_passwords_using_reversible_encryption'
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Minimum_Password_Age = 1
              Name = 'Minimum_Password_Age'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Account_lockout_threshold = 3
              Name = 'Account_lockout_threshold'
         }

         AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Maximum_Password_Age = 60
              Name = 'Maximum_Password_Age'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Enforce_password_history = 24
              Name = 'Enforce_password_history'
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 14
         }

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }

         SecurityOption 'SecuritySetting(INF): NewAdministratorName'
         {
              Name = 'Accounts_Rename_administrator_account'
              Accounts_Rename_administrator_account = 'X_Admin'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Account_lockout_duration = 15
              Name = 'Account_lockout_duration'
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
         }

         SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Accounts_Guest_account_status = 'Disabled'
              Name = 'Accounts_Guest_account_status'
         }

         AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Name = 'Reset_account_lockout_counter_after'
              Reset_account_lockout_counter_after = 15
         }

         SecurityOption 'SecuritySetting(INF): NewGuestName'
         {
              Name = 'Accounts_Rename_guest_account'
              Accounts_Rename_guest_account = 'Visitor'
         }

         <#SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
         {
              Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
              System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
         {
              Name = 'Network_security_LAN_Manager_authentication_level'
              Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
         {
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         {
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
         {
              Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
              User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
         {
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
         {
              Name = 'Interactive_logon_Machine_inactivity_limit'
              Interactive_logon_Machine_inactivity_limit = '900'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
         {
              Name = 'Domain_member_Disable_machine_account_password_changes'
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
         {
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Name = 'Domain_member_Maximum_machine_account_password_age'
              Domain_member_Maximum_machine_account_password_age = '30'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         {
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
         {
              Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
              Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
         }#>

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
         {
              Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
              Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'O:BAG:BAD:(A;;RC;;;BA)'
         }

         <#SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         {
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
         {
              Name = 'Network_security_LDAP_client_signing_requirements'
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         {
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         {
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         {
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
         {
              Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
              Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
         {
              Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
              Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         {
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
         {
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
         {
              Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
              Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
         {
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         {
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
         {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
         {
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
         {
              Name = 'Interactive_logon_Smart_card_removal_behavior'
              Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         {
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         {
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
         {
              Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
              Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         {
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         }#>

         <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Force = $True
              Policy = 'Act_as_part_of_the_operating_system'
              Identity = @('')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Force = $True
              Policy = 'Take_ownership_of_files_or_other_objects'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Force = $True
              Policy = 'Manage_auditing_and_security_log'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
         {
              Force = $True
              Policy = 'Deny_log_on_as_a_batch_job'
              Identity = @('ADD YOUR DOMAIN ADMINS', 'ADD YOUR ENTERPRISE ADMINS', '*S-1-5-32-546')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Force = $True
              Policy = 'Load_and_unload_device_drivers'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Force = $True
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Identity = @('')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Force = $True
              Policy = 'Impersonate_a_client_after_authentication'
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Force = $True
              Policy = 'Increase_scheduling_priority'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Force = $True
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Identity = @('')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Force = $True
              Policy = 'Create_global_objects'
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Force = $True
              Policy = 'Force_shutdown_from_a_remote_system'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Force = $True
              Policy = 'Debug_programs'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Force = $True
              Policy = 'Create_permanent_shared_objects'
              Identity = @('')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Force = $True
              Policy = 'Restore_files_and_directories'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Force = $True
              Policy = 'Access_this_computer_from_the_network'
              Identity = @('*S-1-5-32-544', '*S-1-5-11')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Force = $True
              Policy = 'Create_a_token_object'
              Identity = @('')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Force = $True
              Policy = 'Generate_security_audits'
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Force = $True
              Policy = 'Allow_log_on_locally'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Force = $True
              Policy = 'Deny_log_on_locally'
              Identity = @('ADD YOUR DOMAIN ADMINS', 'ADD YOUR ENTERPRISE ADMINS', '*S-1-5-32-546')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Force = $True
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Identity = @('ADD YOUR DOMAIN ADMINS', 'ADD YOUR ENTERPRISE ADMINS', '*S-1-5-32-546', '*S-1-5-113')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Force = $True
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Identity = @('ADD YOUR DOMAIN ADMINS', 'ADD YOUR ENTERPRISE ADMINS', '*S-1-5-32-546', '*S-1-5-113')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Force = $True
              Policy = 'Perform_volume_maintenance_tasks'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Force = $True
              Policy = 'Modify_firmware_environment_values'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Force = $True
              Policy = 'Create_symbolic_links'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Force = $True
              Policy = 'Back_up_files_and_directories'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
         {
              Force = $True
              Policy = 'Deny_log_on_as_a_service'
              Identity = @('ADD YOUR DOMAIN ADMINS', 'ADD YOUR ENTERPRISE ADMINS')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Force = $True
              Policy = 'Lock_pages_in_memory'
              Identity = @('')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Force = $True
              Policy = 'Create_a_pagefile'
              Identity = @('*S-1-5-32-544')
         }#>

         <#UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Force = $True
              Policy = 'Profile_single_process'
              Identity = @('*S-1-5-32-544')
         }#>

         <#AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Store_passwords_using_reversible_encryption = 'Disabled'
              Name = 'Store_passwords_using_reversible_encryption'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Minimum_Password_Age = 1
              Name = 'Minimum_Password_Age'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Account_lockout_threshold = 3
              Name = 'Account_lockout_threshold'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Maximum_Password_Age = 60
              Name = 'Maximum_Password_Age'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Enforce_password_history = 24
              Name = 'Enforce_password_history'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 14
         }#>

         <#AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }#>

         <#SecurityOption 'SecuritySetting(INF): NewAdministratorName'
         {
              Name = 'Accounts_Rename_administrator_account'
              Accounts_Rename_administrator_account = 'X_Admin'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Account_lockout_duration = 15
              Name = 'Account_lockout_duration'
         }#>

         <#SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
         }#>

         <#SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Accounts_Guest_account_status = 'Disabled'
              Name = 'Accounts_Guest_account_status'
         }#>

         <#AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Name = 'Reset_account_lockout_counter_after'
              Reset_account_lockout_counter_after = 15
         }#>

         <#SecurityOption 'SecuritySetting(INF): NewGuestName'
         {
              Name = 'Accounts_Rename_guest_account'
              Accounts_Rename_guest_account = 'Visitor'
         }#>

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
