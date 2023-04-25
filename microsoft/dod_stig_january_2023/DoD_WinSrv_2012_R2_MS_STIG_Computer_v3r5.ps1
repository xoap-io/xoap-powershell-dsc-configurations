
Configuration DoD_WinSrv_2012_R2_MS_STIG_Computer_v3r5
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node DoD_WinSrv_2012_R2_MS_STIG_Computer_v3r5
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
         {
              ValueName = 'EnumerateAdministrators'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
         {
              ValueName = 'NoDriveTypeAutoRun'
              ValueData = 255
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
         {
              ValueName = 'NoInternetOpenWith'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
         {
              ValueName = 'PreXPSP2ShellProtocolBehavior'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
         {
              ValueName = 'NoAutorun'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
         {
              ValueName = 'LocalSourcePath'
              ValueData = $null
              ValueType = 'ExpandString'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
         {
              ValueName = 'UseWindowsUpdate'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
         }

         RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
         {
              ValueName = 'RepairContentServerSource'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
         }

         RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
         {
              ValueName = 'DisableBkGndGroupPolicy'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
         {
              ValueName = 'MSAOptional'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
         {
              ValueName = 'DisableAutomaticRestartSignOn'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
         {
              ValueName = 'LocalAccountTokenFilterPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
         {
              ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
         {
              ValueName = 'AutoAdminLogon'
              ValueData = '0'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
         {
              ValueName = 'ScreenSaverGracePeriod'
              ValueData = '5'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
         {
              ValueName = 'Enabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Biometrics'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
         {
              ValueName = 'BlockUserInputMethodsForSignIn'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Control Panel\International'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
         {
              ValueName = 'MicrosoftEventVwrDisableLinks'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\EventViewer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
         {
              ValueName = 'DisableEnclosureDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
         {
              ValueName = 'AllowBasicAuthInClear'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
         {
              ValueName = 'Disabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Peernet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
         {
              ValueName = 'CEIPEnable'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\SQMClient\Windows'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
         {
              ValueName = 'DisableInventory'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\AppCompat'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
         {
              ValueName = 'DisablePcaUI'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\AppCompat'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
         {
              ValueName = 'AllowAllTrustedApps'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Appx'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
         {
              ValueName = 'DisablePasswordReveal'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\CredUI'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
         {
              ValueName = 'PreventDeviceMetadataFromNetwork'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Device Metadata'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
         {
              ValueName = 'AllowRemoteRPC'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
         {
              ValueName = 'DisableSystemRestore'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
         {
              ValueName = 'DisableSendGenericDriverNotFoundToWER'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
         {
              ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
         {
              ValueName = 'DontSearchWindowsUpdate'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DriverSearching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
         {
              ValueName = 'DontPromptForWindowsUpdate'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DriverSearching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
         {
              ValueName = 'SearchOrderConfig'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DriverSearching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
         {
              ValueName = 'DriverServerSelection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\DriverSearching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\EventLog\Application'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\EventLog\Security'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\EventLog\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
         {
              ValueName = 'NoHeapTerminationOnCorruption'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
         {
              ValueName = 'NoAutoplayfornonVolume'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
         {
              ValueName = 'NoDataExecutionPrevention'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
         {
              ValueName = 'NoUseStoreOpenWith'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
         {
              ValueName = 'NoBackgroundPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
         {
              ValueName = 'NoGPOListChanges'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
         {
              ValueName = 'PreventHandwritingErrorReports'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
         {
              ValueName = 'SafeForScripting'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
         {
              ValueName = 'EnableUserControl'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
         {
              ValueName = 'DisableLUAPatching'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
         {
              ValueName = 'AlwaysInstallElevated'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
         {
              ValueName = 'EnableLLTDIO'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
         {
              ValueName = 'AllowLLTDIOOnDomain'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
         {
              ValueName = 'AllowLLTDIOOnPublicNet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
         {
              ValueName = 'ProhibitLLTDIOOnPrivateNet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
         {
              ValueName = 'EnableRspndr'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
         {
              ValueName = 'AllowRspndrOnDomain'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
         {
              ValueName = 'AllowRspndrOnPublicNet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
         {
              ValueName = 'ProhibitRspndrOnPrivateNet'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LLTD'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
         {
              ValueName = 'DisableLocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
         {
              ValueName = 'NC_AllowNetBridge_NLA'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Network Connections'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
         {
              ValueName = 'NC_StdDomainUserSetLocation'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Network Connections'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
         {
              ValueName = 'NoLockScreenSlideshow'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
         {
              ValueName = 'EnableScriptBlockLogging'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              ValueName = 'EnableScriptBlockInvocationLogging'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
         {
              ValueName = 'DisableQueryRemoteServer'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
         {
              ValueName = 'EnableQueryRemoteServer'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
         {
              ValueName = 'EnumerateLocalUsers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
         {
              ValueName = 'DisableLockScreenAppNotifications'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
         {
              ValueName = 'DontDisplayNetworkSelectionUI'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
         {
              ValueName = 'EnableSmartScreen'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
         {
              ValueName = 'PreventHandwritingDataSharing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\TabletPC'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
         {
              ValueName = 'Force_Tunneling'
              ValueData = 'Enabled'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
         {
              ValueName = 'EnableRegistrars'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
         {
              ValueName = 'DisableUPnPRegistrar'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
         {
              ValueName = 'DisableInBand802DOT11Registrar'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
         {
              ValueName = 'DisableFlashConfigRegistrar'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
         {
              ValueName = 'DisableWPDRegistrar'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
         {
              ValueName = 'MaxWCNDeviceNumber'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
         {
              ValueName = 'HigherPrecedenceRegistrar'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
         {
              ValueName = 'DisableWcnUi'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WCN\UI'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
         {
              ValueName = 'ScenarioExecutionEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
         {
              ValueName = 'AllowDigest'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
         {
              ValueName = 'DisableRunAs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
         {
              ValueName = 'DisableHTTPPrinting'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Printers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
         {
              ValueName = 'DisableWebPnPDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Printers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
         {
              ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Printers'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
         {
              ValueName = 'RestrictRemoteClients'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Rpc'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
         {
              ValueName = 'fAllowToGetHelp'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
         {
              ValueName = 'fAllowFullControl'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
         {
              ValueName = 'MaxTicketExpiry'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
         {
              ValueName = 'MaxTicketExpiryUnits'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
         {
              ValueName = 'fUseMailto'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
         {
              ValueName = 'fPromptForPassword'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
         {
              ValueName = 'MinEncryptionLevel'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
         {
              ValueName = 'PerSessionTempDir'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
         {
              ValueName = 'DeleteTempDirsOnExit'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
         {
              ValueName = 'fAllowUnsolicited'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
         {
              ValueName = 'fAllowUnsolicitedFullControl'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
         {
              ValueName = 'fEncryptRPCTraffic'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
         {
              ValueName = 'DisablePasswordSaving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
         {
              ValueName = 'fDisableCdm'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
         {
              ValueName = 'LoggingEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
         {
              ValueName = 'fDisableCcm'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
         {
              ValueName = 'fDisableLPT'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
         {
              ValueName = 'fDisablePNPRedir'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
         {
              ValueName = 'fEnableSmartCard'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
         {
              ValueName = 'RedirectOnlyDefaultClientPrinter'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services'
         }

         <#RegistryPolicyFile 'DELVALS_\Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
         {
              ValueName = ''
              Exclusive = $True
              ValueData = ''
              Ensure = 'Present'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
         {
              ValueName = 'DisableAutoUpdate'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\WindowsMediaPlayer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
         {
              ValueName = 'GroupPrivacyAcceptance'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\WindowsMediaPlayer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
         {
              ValueName = 'DisableOnline'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\policies\Microsoft\WMDRM'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
         {
              ValueName = 'UseLogonCredential'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
         {
              ValueName = 'SafeDllSearchMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
         {
              ValueName = 'DriverLoadPolicy'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
         {
              ValueName = 'WarningLevel'
              ValueData = 90
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
         {
              ValueName = 'NoDefaultExempt'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
         {
              ValueName = 'SMB1'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
         {
              ValueName = 'Start'
              ValueData = 4
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
         {
              ValueName = 'NoNameReleaseOnDemand'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
         {
              ValueName = 'EnableICMPRedirect'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
         {
              ValueName = 'PerformRouterDiscovery'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
         {
              ValueName = 'KeepAliveTime'
              ValueData = 300000
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
         {
              ValueName = 'TcpMaxDataRetransmissions'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
         {
              ValueName = 'EnableIPAutoConfigurationLimits'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
         {
              ValueName = 'TcpMaxDataRetransmissions'
              ValueData = 3
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

         AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
         {
              Name = 'Other Account Management Events'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
         {
              Name = 'Other Account Management Events'
              Ensure = 'Absent'
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

         AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
         {
              Name = 'Account Lockout'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
         {
              Name = 'Logoff'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
         {
              Name = 'Logoff'
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

         AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
         {
              Name = 'Central Policy Staging'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
         {
              Name = 'Central Policy Staging'
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
              Ensure = 'Present'
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

         AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
         {
              Name = 'Authorization Policy Change'
              Ensure = 'Absent'
              AuditFlag = 'Failure'
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

         AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
         {
              Name = 'IPsec Driver'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
         {
              Name = 'IPsec Driver'
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

         <#Service 'Services(INF): SCPolicySvc'
         {
              Name = 'SCPolicySvc'
              State = 'Running'
         }#>

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
         {
              Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
              Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
         {
              Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
              Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
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

         SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
         {
              Name = 'Domain_member_Disable_machine_account_password_changes'
              Domain_member_Disable_machine_account_password_changes = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
         {
              Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
              Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
         {
              Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
              Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
         {
              Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_always'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
         {
              Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
              Network_access_Shares_that_can_be_accessed_anonymously = 'String'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         {
              User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
              Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
         {
              Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
              Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
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

         SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
         {
              Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
              Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         {
              Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
              Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         {
              Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
              Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
         {
              User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
              Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
         }

         SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         {
              Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
              Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
              Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
         {
              Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
              Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
         {
              Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
              Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
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

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         {
              Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
              Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
         {
              Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
              Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
         {
              Interactive_logon_Do_not_display_last_user_name = 'Enabled'
              Name = 'Interactive_logon_Do_not_display_last_user_name'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
         {
              Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
              User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
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

         SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
         {
              Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
              Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
         }

         SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
         {
              Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
              Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         {
              System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
              Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
         {
              Interactive_logon_Machine_inactivity_limit = '900'
              Name = 'Interactive_logon_Machine_inactivity_limit'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
         {
              Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
              Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'String'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
         {
              Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
              Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
         {
              Name = 'Microsoft_network_server_Digitally_sign_communications_always'
              Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
         {
              Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
              Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
         {
              Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
              Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
         {
              Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
              Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
         {
              Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
              Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
         {
              Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
              User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
         {
              Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
              Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
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

         SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
         {
              Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
              Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
         {
              Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
              User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         {
              System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
              Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
         }

         SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
         {
              Name = 'Audit_Audit_the_access_of_global_system_objects'
              Audit_Audit_the_access_of_global_system_objects = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
         {
              Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
              User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         }

         SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
         {
              Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
              Name = 'Devices_Allowed_to_format_and_eject_removable_media'
         }

         SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
         {
              System_settings_Optional_subsystems = 'String'
              Name = 'System_settings_Optional_subsystems'
         }

         SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
         {
              Name = 'Network_access_Remotely_accessible_registry_paths'
              Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
         }

         SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         {
              Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
              Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
         }

         SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         {
              Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
              Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
         }

         SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
         {
              Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
              Name = 'Devices_Prevent_users_from_installing_printer_drivers'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
         {
              Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
              Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
         }

         SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
         {
              Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
              System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Name = 'Domain_member_Maximum_machine_account_password_age'
              Domain_member_Maximum_machine_account_password_age = '30'
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
         {
              Policy = 'Load_and_unload_device_drivers'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
         {
              Policy = 'Take_ownership_of_files_or_other_objects'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
         {
              Policy = 'Deny_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
         {
              Policy = 'Deny_log_on_as_a_batch_job'
              Force = $True
              Identity = @('*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
         {
              Policy = 'Back_up_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
         {
              Policy = 'Allow_log_on_through_Remote_Desktop_Services'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
         {
              Policy = 'Create_symbolic_links'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
         {
              Policy = 'Manage_auditing_and_security_log'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
         {
              Policy = 'Deny_log_on_through_Remote_Desktop_Services'
              Force = $True
              Identity = @('*S-1-5-113', '*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Policy = 'Lock_pages_in_memory'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
         {
              Policy = 'Increase_scheduling_priority'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
         {
              Policy = 'Restore_files_and_directories'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
         {
              Policy = 'Create_a_token_object'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
         {
              Policy = 'Create_permanent_shared_objects'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Policy = 'Create_global_objects'
              Force = $True
              Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
         {
              Policy = 'Deny_log_on_as_a_service'
              Force = $True
              Identity = @('ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
         {
              Policy = 'Deny_access_to_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-113', '*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
         {
              Policy = 'Access_this_computer_from_the_network'
              Force = $True
              Identity = @('*S-1-5-11', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
         {
              Policy = 'Generate_security_audits'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         SecurityOption 'SecuritySetting(INF): NewGuestName'
         {
              Accounts_Rename_guest_account = 'Visitor'
              Name = 'Accounts_Rename_guest_account'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
         {
              Name = 'Enforce_password_history'
              Enforce_password_history = 24
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
         {
              Name = 'Minimum_Password_Length'
              Minimum_Password_Length = 14
         }

         AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
         {
              Minimum_Password_Age = 1
              Name = 'Minimum_Password_Age'
         }

         SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
         {
              Name = 'Network_security_Force_logoff_when_logon_hours_expire'
              Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
         {
              Reset_account_lockout_counter_after = 15
              Name = 'Reset_account_lockout_counter_after'
         }

         AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
         {
              Name = 'Maximum_Password_Age'
              Maximum_Password_Age = 60
         }

         AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
         {
              Name = 'Store_passwords_using_reversible_encryption'
              Store_passwords_using_reversible_encryption = 'Disabled'
         }

         AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
         {
              Name = 'Account_lockout_threshold'
              Account_lockout_threshold = 3
         }

         AccountPolicy 'SecuritySetting(INF): LockoutDuration'
         {
              Name = 'Account_lockout_duration'
              Account_lockout_duration = 15
         }

         SecurityOption 'SecuritySetting(INF): NewAdministratorName'
         {
              Accounts_Rename_administrator_account = 'X_Admin'
              Name = 'Accounts_Rename_administrator_account'
         }

         SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
         {
              Accounts_Guest_account_status = 'Disabled'
              Name = 'Accounts_Guest_account_status'
         }

         AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
         {
              Name = 'Password_must_meet_complexity_requirements'
              Password_must_meet_complexity_requirements = 'Enabled'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
