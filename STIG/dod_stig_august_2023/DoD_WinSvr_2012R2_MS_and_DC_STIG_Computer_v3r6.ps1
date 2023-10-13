Configuration 'DoD_WinSvr_2012R2_MS_and_DC_STIG_Computer_v3r6'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
	
     Node 'DoD_WinSvr_2012R2_MS_and_DC_STIG_Computer_v3r6'
	{
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
               ValueType = 'Dword'
               ValueName = 'EnumerateAdministrators'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 255
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoDriveTypeAutoRun'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoInternetOpenWith'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'PreXPSP2ShellProtocolBehavior'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoAutorun'
          }
 
          <#
               This MultiString Value has a value of $null, 
                Some Security Policies require Registry Values to be $null
                If you believe ' ' is the correct value for this string, you may change it here.
          #>
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = $null
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
               ValueType = 'ExpandString'
               ValueName = 'LocalSourcePath'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
               ValueType = 'Dword'
               ValueName = 'UseWindowsUpdate'
          }
 
          RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'RepairContentServerSource'
          }
 
          RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'DisableBkGndGroupPolicy'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
               ValueType = 'Dword'
               ValueName = 'MSAOptional'
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
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = '0'
               Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
               ValueType = 'String'
               ValueName = 'AutoAdminLogon'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = '5'
               Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
               ValueType = 'String'
               ValueName = 'ScreenSaverGracePeriod'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Biometrics'
               ValueType = 'Dword'
               ValueName = 'Enabled'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Control Panel\International'
               ValueType = 'Dword'
               ValueName = 'BlockUserInputMethodsForSignIn'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\EventViewer'
               ValueType = 'Dword'
               ValueName = 'MicrosoftEventVwrDisableLinks'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
               ValueType = 'Dword'
               ValueName = 'DisableEnclosureDownload'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
               ValueType = 'Dword'
               ValueName = 'AllowBasicAuthInClear'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Peernet'
               ValueType = 'Dword'
               ValueName = 'Disabled'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
               ValueType = 'Dword'
               ValueName = 'DCSettingIndex'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
               ValueType = 'Dword'
               ValueName = 'ACSettingIndex'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\SQMClient\Windows'
               ValueType = 'Dword'
               ValueName = 'CEIPEnable'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\AppCompat'
               ValueType = 'Dword'
               ValueName = 'DisableInventory'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\AppCompat'
               ValueType = 'Dword'
               ValueName = 'DisablePcaUI'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Appx'
               ValueType = 'Dword'
               ValueName = 'AllowAllTrustedApps'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\CredUI'
               ValueType = 'Dword'
               ValueName = 'DisablePasswordReveal'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Device Metadata'
               ValueType = 'Dword'
               ValueName = 'PreventDeviceMetadataFromNetwork'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'AllowRemoteRPC'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'DisableSystemRestore'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'DisableSendGenericDriverNotFoundToWER'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'DontSearchWindowsUpdate'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'DontPromptForWindowsUpdate'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'SearchOrderConfig'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'DriverServerSelection'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 32768
               Key = 'Software\policies\Microsoft\Windows\EventLog\Application'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 196608
               Key = 'Software\policies\Microsoft\Windows\EventLog\Security'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 32768
               Key = 'Software\policies\Microsoft\Windows\EventLog\Setup'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 32768
               Key = 'Software\policies\Microsoft\Windows\EventLog\System'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoHeapTerminationOnCorruption'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoAutoplayfornonVolume'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoDataExecutionPrevention'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoUseStoreOpenWith'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
               ValueType = 'Dword'
               ValueName = 'NoBackgroundPolicy'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
               ValueType = 'Dword'
               ValueName = 'NoGPOListChanges'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\HandwritingErrorReports'
               ValueType = 'Dword'
               ValueName = 'PreventHandwritingErrorReports'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'SafeForScripting'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'EnableUserControl'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'DisableLUAPatching'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'AlwaysInstallElevated'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'EnableLLTDIO'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowLLTDIOOnDomain'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowLLTDIOOnPublicNet'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'ProhibitLLTDIOOnPrivateNet'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'EnableRspndr'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowRspndrOnDomain'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowRspndrOnPublicNet'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'ProhibitRspndrOnPrivateNet'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\LocationAndSensors'
               ValueType = 'Dword'
               ValueName = 'DisableLocation'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Network Connections'
               ValueType = 'Dword'
               ValueName = 'NC_AllowNetBridge_NLA'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Network Connections'
               ValueType = 'Dword'
               ValueName = 'NC_StdDomainUserSetLocation'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Personalization'
               ValueType = 'Dword'
               ValueName = 'NoLockScreenSlideshow'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
               ValueType = 'Dword'
               ValueName = 'EnableScriptBlockLogging'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'EnableScriptBlockInvocationLogging'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
               ValueType = 'Dword'
               ValueName = 'DisableQueryRemoteServer'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
               ValueType = 'Dword'
               ValueName = 'EnableQueryRemoteServer'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'EnumerateLocalUsers'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'DisableLockScreenAppNotifications'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'DontDisplayNetworkSelectionUI'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'EnableSmartScreen'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\TabletPC'
               ValueType = 'Dword'
               ValueName = 'PreventHandwritingDataSharing'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 'Enabled'
               Key = 'Software\policies\Microsoft\Windows\TCPIP\v6Transition'
               ValueType = 'String'
               ValueName = 'Force_Tunneling'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'EnableRegistrars'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableUPnPRegistrar'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableInBand802DOT11Registrar'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableFlashConfigRegistrar'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableWPDRegistrar'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'MaxWCNDeviceNumber'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'HigherPrecedenceRegistrar'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\WCN\UI'
               ValueType = 'Dword'
               ValueName = 'DisableWcnUi'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
               ValueType = 'Dword'
               ValueName = 'ScenarioExecutionEnabled'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
               ValueType = 'Dword'
               ValueName = 'AllowBasic'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
               ValueType = 'Dword'
               ValueName = 'AllowUnencryptedTraffic'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
               ValueType = 'Dword'
               ValueName = 'AllowDigest'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
               ValueType = 'Dword'
               ValueName = 'AllowBasic'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
               ValueType = 'Dword'
               ValueName = 'AllowUnencryptedTraffic'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
               ValueType = 'Dword'
               ValueName = 'DisableRunAs'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Printers'
               ValueType = 'Dword'
               ValueName = 'DisableHTTPPrinting'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Printers'
               ValueType = 'Dword'
               ValueName = 'DisableWebPnPDownload'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Printers'
               ValueType = 'Dword'
               ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Rpc'
               ValueType = 'Dword'
               ValueName = 'RestrictRemoteClients'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fAllowToGetHelp'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'fAllowFullControl'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'MaxTicketExpiry'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'MaxTicketExpiryUnits'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'fUseMailto'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fPromptForPassword'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'MinEncryptionLevel'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'PerSessionTempDir'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'DeleteTempDirsOnExit'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fAllowUnsolicited'
          }
 
          RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'fAllowUnsolicitedFullControl'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fEncryptRPCTraffic'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'DisablePasswordSaving'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisableCdm'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'LoggingEnabled'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisableCcm'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisableLPT'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisablePNPRedir'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fEnableSmartCard'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'RedirectOnlyDefaultClientPrinter'
          }
 
          <#RegistryPolicyFile 'DELVALS_\Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Exclusive = $True
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
               Ensure = 'Present'
               ValueType = 'String'
               ValueName = ''
          }#>
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
               ValueType = 'Dword'
               ValueName = 'DisableAutoUpdate'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
               ValueType = 'Dword'
               ValueName = 'GroupPrivacyAcceptance'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\WMDRM'
               ValueType = 'Dword'
               ValueName = 'DisableOnline'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
               ValueType = 'Dword'
               ValueName = 'UseLogonCredential'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Control\Session Manager'
               ValueType = 'Dword'
               ValueName = 'SafeDllSearchMode'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
               ValueType = 'Dword'
               ValueName = 'DriverLoadPolicy'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 90
               Key = 'SYSTEM\CurrentControlSet\Services\Eventlog\Security'
               ValueType = 'Dword'
               ValueName = 'WarningLevel'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'SYSTEM\CurrentControlSet\Services\IPSEC'
               ValueType = 'Dword'
               ValueName = 'NoDefaultExempt'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
               ValueType = 'Dword'
               ValueName = 'SMB1'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 4
               Key = 'SYSTEM\CurrentControlSet\Services\MrxSmb10'
               ValueType = 'Dword'
               ValueName = 'Start'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
               ValueType = 'Dword'
               ValueName = 'NoNameReleaseOnDemand'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'DisableIPSourceRouting'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'EnableICMPRedirect'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'PerformRouterDiscovery'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 300000
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'KeepAliveTime'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'TcpMaxDataRetransmissions'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'EnableIPAutoConfigurationLimits'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
               ValueType = 'Dword'
               ValueName = 'DisableIPSourceRouting'
          }
 
          RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
               ValueType = 'Dword'
               ValueName = 'TcpMaxDataRetransmissions'
          }
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
               ValueType = 'Dword'
               ValueName = 'SaveZoneInformation'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\HideZoneInfoOnProperties'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
               ValueType = 'Dword'
               ValueName = 'HideZoneInfoOnProperties'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ScanWithAntiVirus'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
               ValueType = 'Dword'
               ValueName = 'ScanWithAntiVirus'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInplaceSharing'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoInplaceSharing'
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
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\NoImplicitFeedback'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
               ValueType = 'Dword'
               ValueName = 'NoImplicitFeedback'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\NoExplicitFeedback'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0'
               ValueType = 'Dword'
               ValueName = 'NoExplicitFeedback'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveActive'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = '1'
               Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
               ValueType = 'String'
               ValueName = 'ScreenSaveActive'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaverIsSecure'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = '1'
               Key = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
               ValueType = 'String'
               ValueName = 'ScreenSaverIsSecure'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
               ValueType = 'Dword'
               ValueName = 'NoCloudApplicationNotification'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoToastApplicationNotificationOnLockScreen'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
               ValueType = 'Dword'
               ValueName = 'NoToastApplicationNotificationOnLockScreen'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer\PreventCodecDownload'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer'
               ValueType = 'Dword'
               ValueName = 'PreventCodecDownload'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
               ValueType = 'Dword'
               ValueName = 'EnumerateAdministrators'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 255
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoDriveTypeAutoRun'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoInternetOpenWith'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'PreXPSP2ShellProtocolBehavior'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoAutorun'
          }#>
 
          <#
               This MultiString Value has a value of $null, 
                Some Security Policies require Registry Values to be $null
                If you believe ' ' is the correct value for this string, you may change it here.
          #>
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = $null
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
               ValueType = 'ExpandString'
               ValueName = 'LocalSourcePath'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
               ValueType = 'Dword'
               ValueName = 'UseWindowsUpdate'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'RepairContentServerSource'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'DisableBkGndGroupPolicy'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
               ValueType = 'Dword'
               ValueName = 'MSAOptional'
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
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = '0'
               Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
               ValueType = 'String'
               ValueName = 'AutoAdminLogon'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = '5'
               Key = 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
               ValueType = 'String'
               ValueName = 'ScreenSaverGracePeriod'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Biometrics'
               ValueType = 'Dword'
               ValueName = 'Enabled'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Control Panel\International'
               ValueType = 'Dword'
               ValueName = 'BlockUserInputMethodsForSignIn'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\EventViewer'
               ValueType = 'Dword'
               ValueName = 'MicrosoftEventVwrDisableLinks'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
               ValueType = 'Dword'
               ValueName = 'DisableEnclosureDownload'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
               ValueType = 'Dword'
               ValueName = 'AllowBasicAuthInClear'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Peernet'
               ValueType = 'Dword'
               ValueName = 'Disabled'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
               ValueType = 'Dword'
               ValueName = 'DCSettingIndex'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
               ValueType = 'Dword'
               ValueName = 'ACSettingIndex'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\SQMClient\Windows'
               ValueType = 'Dword'
               ValueName = 'CEIPEnable'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\AppCompat'
               ValueType = 'Dword'
               ValueName = 'DisableInventory'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\AppCompat'
               ValueType = 'Dword'
               ValueName = 'DisablePcaUI'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Appx'
               ValueType = 'Dword'
               ValueName = 'AllowAllTrustedApps'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\CredUI'
               ValueType = 'Dword'
               ValueName = 'DisablePasswordReveal'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Device Metadata'
               ValueType = 'Dword'
               ValueName = 'PreventDeviceMetadataFromNetwork'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'AllowRemoteRPC'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'DisableSystemRestore'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'DisableSendGenericDriverNotFoundToWER'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
               ValueType = 'Dword'
               ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'DontSearchWindowsUpdate'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'DontPromptForWindowsUpdate'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'SearchOrderConfig'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\DriverSearching'
               ValueType = 'Dword'
               ValueName = 'DriverServerSelection'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 32768
               Key = 'Software\policies\Microsoft\Windows\EventLog\Application'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 196608
               Key = 'Software\policies\Microsoft\Windows\EventLog\Security'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 32768
               Key = 'Software\policies\Microsoft\Windows\EventLog\Setup'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 32768
               Key = 'Software\policies\Microsoft\Windows\EventLog\System'
               ValueType = 'Dword'
               ValueName = 'MaxSize'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoHeapTerminationOnCorruption'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoAutoplayfornonVolume'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoDataExecutionPrevention'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Explorer'
               ValueType = 'Dword'
               ValueName = 'NoUseStoreOpenWith'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
               ValueType = 'Dword'
               ValueName = 'NoBackgroundPolicy'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
               ValueType = 'Dword'
               ValueName = 'NoGPOListChanges'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\HandwritingErrorReports'
               ValueType = 'Dword'
               ValueName = 'PreventHandwritingErrorReports'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'SafeForScripting'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'EnableUserControl'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'DisableLUAPatching'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Installer'
               ValueType = 'Dword'
               ValueName = 'AlwaysInstallElevated'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'EnableLLTDIO'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowLLTDIOOnDomain'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowLLTDIOOnPublicNet'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'ProhibitLLTDIOOnPrivateNet'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'EnableRspndr'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowRspndrOnDomain'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'AllowRspndrOnPublicNet'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\LLTD'
               ValueType = 'Dword'
               ValueName = 'ProhibitRspndrOnPrivateNet'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\LocationAndSensors'
               ValueType = 'Dword'
               ValueName = 'DisableLocation'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\Network Connections'
               ValueType = 'Dword'
               ValueName = 'NC_AllowNetBridge_NLA'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Network Connections'
               ValueType = 'Dword'
               ValueName = 'NC_StdDomainUserSetLocation'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\Personalization'
               ValueType = 'Dword'
               ValueName = 'NoLockScreenSlideshow'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
               ValueType = 'Dword'
               ValueName = 'EnableScriptBlockLogging'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'EnableScriptBlockInvocationLogging'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
               ValueType = 'Dword'
               ValueName = 'DisableQueryRemoteServer'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
               ValueType = 'Dword'
               ValueName = 'EnableQueryRemoteServer'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'EnumerateLocalUsers'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'DisableLockScreenAppNotifications'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'DontDisplayNetworkSelectionUI'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'Software\policies\Microsoft\Windows\System'
               ValueType = 'Dword'
               ValueName = 'EnableSmartScreen'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\TabletPC'
               ValueType = 'Dword'
               ValueName = 'PreventHandwritingDataSharing'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 'Enabled'
               Key = 'Software\policies\Microsoft\Windows\TCPIP\v6Transition'
               ValueType = 'String'
               ValueName = 'Force_Tunneling'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'EnableRegistrars'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableUPnPRegistrar'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableInBand802DOT11Registrar'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableFlashConfigRegistrar'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               ValueType = 'Dword'
               ValueName = 'DisableWPDRegistrar'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'MaxWCNDeviceNumber'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'HigherPrecedenceRegistrar'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\WCN\UI'
               ValueType = 'Dword'
               ValueName = 'DisableWcnUi'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
               ValueType = 'Dword'
               ValueName = 'ScenarioExecutionEnabled'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
               ValueType = 'Dword'
               ValueName = 'AllowBasic'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
               ValueType = 'Dword'
               ValueName = 'AllowUnencryptedTraffic'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
               ValueType = 'Dword'
               ValueName = 'AllowDigest'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
               ValueType = 'Dword'
               ValueName = 'AllowBasic'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
               ValueType = 'Dword'
               ValueName = 'AllowUnencryptedTraffic'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
               ValueType = 'Dword'
               ValueName = 'DisableRunAs'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Printers'
               ValueType = 'Dword'
               ValueName = 'DisableHTTPPrinting'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Printers'
               ValueType = 'Dword'
               ValueName = 'DisableWebPnPDownload'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Printers'
               ValueType = 'Dword'
               ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fAllowToGetHelp'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'fAllowFullControl'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'MaxTicketExpiry'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'MaxTicketExpiryUnits'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'fUseMailto'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fPromptForPassword'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'MinEncryptionLevel'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'PerSessionTempDir'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'DeleteTempDirsOnExit'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fAllowUnsolicited'
          }#>
 
          <#RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               Ensure = 'Absent'
               ValueType = 'String'
               ValueName = 'fAllowUnsolicitedFullControl'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fEncryptRPCTraffic'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'DisablePasswordSaving'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisableCdm'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'LoggingEnabled'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisableCcm'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisableLPT'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fDisablePNPRedir'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'fEnableSmartCard'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
               ValueType = 'Dword'
               ValueName = 'RedirectOnlyDefaultClientPrinter'
          }#>
 
          <#RegistryPolicyFile 'DELVALS_\Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = ''
               Exclusive = $True
               Key = 'Software\policies\Microsoft\Windows NT\Terminal Services\RAUnsolicit'
               Ensure = 'Present'
               ValueType = 'String'
               ValueName = ''
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
               ValueType = 'Dword'
               ValueName = 'DisableAutoUpdate'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
               ValueType = 'Dword'
               ValueName = 'GroupPrivacyAcceptance'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'Software\policies\Microsoft\WMDRM'
               ValueType = 'Dword'
               ValueName = 'DisableOnline'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
               ValueType = 'Dword'
               ValueName = 'UseLogonCredential'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Control\Session Manager'
               ValueType = 'Dword'
               ValueName = 'SafeDllSearchMode'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
               ValueType = 'Dword'
               ValueName = 'DriverLoadPolicy'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 90
               Key = 'SYSTEM\CurrentControlSet\Services\Eventlog\Security'
               ValueType = 'Dword'
               ValueName = 'WarningLevel'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'SYSTEM\CurrentControlSet\Services\IPSEC'
               ValueType = 'Dword'
               ValueName = 'NoDefaultExempt'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
               ValueType = 'Dword'
               ValueName = 'SMB1'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 4
               Key = 'SYSTEM\CurrentControlSet\Services\MrxSmb10'
               ValueType = 'Dword'
               ValueName = 'Start'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
               ValueType = 'Dword'
               ValueName = 'NoNameReleaseOnDemand'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'DisableIPSourceRouting'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'EnableICMPRedirect'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 0
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'PerformRouterDiscovery'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 300000
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'KeepAliveTime'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'TcpMaxDataRetransmissions'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 1
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
               ValueType = 'Dword'
               ValueName = 'EnableIPAutoConfigurationLimits'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 2
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
               ValueType = 'Dword'
               ValueName = 'DisableIPSourceRouting'
          }#>
 
          <#RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
          {
               TargetType = 'ComputerConfiguration'
               ValueData = 3
               Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
               ValueType = 'Dword'
               ValueName = 'TcpMaxDataRetransmissions'
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
 
          AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
          {
               AuditFlag = 'Success'
               Name = 'Central Policy Staging'
               Ensure = 'Present'
          }
 
           AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
          {
               AuditFlag = 'Failure'
               Name = 'Central Policy Staging'
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
 
          <#AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
          {
               AuditFlag = 'Success'
               Name = 'Central Policy Staging'
               Ensure = 'Present'
          }#>
 
           <#AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
          {
               AuditFlag = 'Failure'
               Name = 'Central Policy Staging'
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
 
          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
          {
               Force = $True
               Policy = 'Deny_log_on_as_a_batch_job'
               Identity = @('*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
          {
               Force = $True
               Policy = 'Load_and_unload_device_drivers'
               Identity = @('*S-1-5-32-544')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
          {
               Force = $True
               Policy = 'Increase_scheduling_priority'
               Identity = @('*S-1-5-32-544')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          {
               Force = $True
               Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
               Identity = @('')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
          {
               Force = $True
               Policy = 'Impersonate_a_client_after_authentication'
               Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
          {
               Force = $True
               Policy = 'Manage_auditing_and_security_log'
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
               Identity = @('*S-1-5-11', '*S-1-5-32-544')
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
               Identity = @('*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
          {
               Force = $True
               Policy = 'Deny_log_on_through_Remote_Desktop_Services'
               Identity = @('*S-1-5-113', '*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
          {
               Force = $True
               Policy = 'Deny_access_to_this_computer_from_the_network'
               Identity = @('*S-1-5-113', '*S-1-5-32-546', 'ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
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
               Identity = @('ADD YOUR ENTERPRISE ADMINS', 'ADD YOUR DOMAIN ADMINS')
          }
 
          UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
          {
               Force = $True
               Policy = 'Lock_pages_in_memory'
               Identity = @('')
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
 
          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
          {
               Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
               Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          {
               Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
               Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
          {
               Name = 'Network_security_LAN_Manager_authentication_level'
               Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
          }
 
          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
          {
               Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
               Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
          }
 
          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
          {
               Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
               Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
          {
               Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
               Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
          {
               Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
               User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
          {
               Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'String'
               Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
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
 
          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
          {
               Name = 'Interactive_logon_Machine_inactivity_limit'
               Interactive_logon_Machine_inactivity_limit = '900'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
          {
               Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
               Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
          {
               Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
               User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
          {
               Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
               User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
          {
               Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
               Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
          {
               Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
               Name = 'Devices_Allowed_to_format_and_eject_removable_media'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
          {
               Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
               Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
          }
 
          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
          {
               Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
               User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
          {
               Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
               System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
          {
               Name = 'System_settings_Optional_subsystems'
               System_settings_Optional_subsystems = 'String'
          }
 
          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
          {
               Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
               Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
          {
               Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
               System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
          {
               Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
               Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
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
               User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
          }
 
          SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
          {
               Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
               Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
          {
               Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
               Network_access_Shares_that_can_be_accessed_anonymously = 'String'
          }
 
          SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
          {
               Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
               Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
          }
 
          SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
          {
               Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
               Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
          {
               Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
               Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
          {
               Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
               System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          {
               User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
               Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          }
 
          SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
          {
               Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
               User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
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
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
          {
               Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
               Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
          {
               Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
               Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
          {
               Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
               Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
          }
 
          SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
          {
               Name = 'Domain_member_Maximum_machine_account_password_age'
               Domain_member_Maximum_machine_account_password_age = '30'
          }
 
          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
          {
               Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
               Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
          }
 
          SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
          {
               Name = 'Audit_Audit_the_access_of_global_system_objects'
               Audit_Audit_the_access_of_global_system_objects = 'Disabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
          {
               Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
               Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
          }
 
          SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
          {
               Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
               Name = 'Microsoft_network_server_Digitally_sign_communications_always'
          }
 
          SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
          {
               Name = 'Devices_Prevent_users_from_installing_printer_drivers'
               Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
          {
               Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
               Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1', 'AES256_HMAC_SHA1', 'FUTURE'
          }
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
          {
               Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
               Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
          {
               Name = 'Domain_member_Disable_machine_account_password_changes'
               Domain_member_Disable_machine_account_password_changes = 'Disabled'
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
 
          SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
          {
               Name = 'Network_security_LDAP_client_signing_requirements'
               Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
          }
 
          SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
          {
               Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
               System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
          }
 
          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
          {
               Name = 'Interactive_logon_Smart_card_removal_behavior'
               Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
          }
 
          SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
          {
               Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
               Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
          }
 
          SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
          {
               Interactive_logon_Do_not_display_last_user_name = 'Enabled'
               Name = 'Interactive_logon_Do_not_display_last_user_name'
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
 
          SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
          {
               Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
               Name = 'Network_access_Remotely_accessible_registry_paths'
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
 
          <#Service 'Services(INF): SCPolicySvc'
          {
               Name = 'SCPolicySvc'
               State = 'Running'
          }#>
 
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
 
          SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
          {
               Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
               Name = 'Network_security_Force_logoff_when_logon_hours_expire'
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
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
          {
               Force = $True
               Policy = 'Deny_log_on_as_a_batch_job'
               Identity = @('*S-1-5-32-546')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
          {
               Force = $True
               Policy = 'Load_and_unload_device_drivers'
               Identity = @('*S-1-5-32-544')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
          {
               Force = $True
               Policy = 'Increase_scheduling_priority'
               Identity = @('*S-1-5-32-544')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          {
               Force = $True
               Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
               Identity = @('*S-1-5-32-544')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
          {
               Force = $True
               Policy = 'Impersonate_a_client_after_authentication'
               Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
          {
               Force = $True
               Policy = 'Manage_auditing_and_security_log'
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
               Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
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
               Identity = @('*S-1-5-32-544', '*S-1-5-11', '*S-1-5-9')
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
               Identity = @('*S-1-5-19', '*S-1-5-20')
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
               Identity = @('*S-1-5-32-546')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
          {
               Force = $True
               Policy = 'Deny_log_on_through_Remote_Desktop_Services'
               Identity = @('*S-1-5-32-546')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
          {
               Force = $True
               Policy = 'Deny_access_to_this_computer_from_the_network'
               Identity = @('*S-1-5-32-546')
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
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
          {
               Force = $True
               Policy = 'Allow_log_on_through_Remote_Desktop_Services'
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
               Identity = @('')
          }#>
 
          <#UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
          {
               Force = $True
               Policy = 'Lock_pages_in_memory'
               Identity = @('')
          }#>
 
          UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
          {
               Force = $True
               Policy = 'Add_workstations_to_domain'
               Identity = @('*S-1-5-32-544')
          }
 
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
 
          <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
          {
               Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
               Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          {
               Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
               Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
          {
               Name = 'Network_security_LAN_Manager_authentication_level'
               Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
          {
               Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
               Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
          {
               Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
               Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
          {
               Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
               Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
          {
               Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
               User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
          {
               Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'lsarpc,netlogon,samr'
               Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
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
 
          <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
          {
               Name = 'Interactive_logon_Machine_inactivity_limit'
               Interactive_logon_Machine_inactivity_limit = '900'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
          {
               Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
               Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
          {
               Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
               User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
          {
               Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
               User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
          {
               Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
               Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
          {
               Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
               Name = 'Devices_Allowed_to_format_and_eject_removable_media'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
          {
               Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
               Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
          {
               Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
               User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
          {
               Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
               System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
          {
               Name = 'System_settings_Optional_subsystems'
               System_settings_Optional_subsystems = 'String'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
          {
               Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
               Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
          {
               Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
               System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
          {
               Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
               Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
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
               User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
          {
               Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
               Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
          {
               Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
               Network_access_Shares_that_can_be_accessed_anonymously = 'String'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
          {
               Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
               Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
          {
               Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
               Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
          {
               Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
               Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
          {
               Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
               System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          {
               User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
               Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
          {
               Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
               User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
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
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
          {
               Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
               Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
          {
               Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
               Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
          {
               Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
               Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
          {
               Name = 'Domain_member_Maximum_machine_account_password_age'
               Domain_member_Maximum_machine_account_password_age = '30'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
          {
               Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
               Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
          {
               Name = 'Audit_Audit_the_access_of_global_system_objects'
               Audit_Audit_the_access_of_global_system_objects = 'Disabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
          {
               Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
               Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
          {
               Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
               Name = 'Microsoft_network_server_Digitally_sign_communications_always'
          }#>
 
          SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
          {
               Name = 'Domain_controller_LDAP_server_signing_requirements'
               Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
          }
 
          <#SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
          {
               Name = 'Devices_Prevent_users_from_installing_printer_drivers'
               Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
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
 
          <#SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
          {
               Name = 'Domain_member_Disable_machine_account_password_changes'
               Domain_member_Disable_machine_account_password_changes = 'Disabled'
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
 
          <#SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
          {
               Name = 'Network_security_LDAP_client_signing_requirements'
               Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
          {
               Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
               System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
          {
               Name = 'Interactive_logon_Smart_card_removal_behavior'
               Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
          }#>
 
          SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
          {
               Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
               Name = 'Domain_controller_Refuse_machine_account_password_changes'
          }
 
          <#SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
          {
               Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
               Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
          }#>
 
          <#SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
          {
               Interactive_logon_Do_not_display_last_user_name = 'Enabled'
               Name = 'Interactive_logon_Do_not_display_last_user_name'
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
 
          <#SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
          {
               Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
               Name = 'Network_access_Remotely_accessible_registry_paths'
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
 
          <#Service 'Services(INF): SCPolicySvc'
          {
               Name = 'SCPolicySvc'
               State = 'Running'
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
 
          <#SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
          {
               Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
               Name = 'Network_security_Force_logoff_when_logon_hours_expire'
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
