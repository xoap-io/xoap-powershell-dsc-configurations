
Configuration 'MSTF_SecurityBaseline_W2K19_Domain_Controller'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'MSTF_SecurityBaseline_W2K19_Domain_Controller'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
         {
              ValueName = 'NoDriveTypeAutoRun'
              ValueData = 255
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

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
         {
              ValueName = 'DisableAutomaticRestartSignOn'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\AllowEncryptionOracle'
         {
              ValueName = 'AllowEncryptionOracle'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
         {
              ValueName = 'EnhancedAntiSpoofing'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
         {
              ValueName = 'DisableEnclosureDownload'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
         {
              ValueName = 'AllowProtectedCreds'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 196608
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
         {
              ValueName = 'MaxSize'
              ValueData = 32768
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
         {
              ValueName = 'NoAutoplayfornonVolume'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
         {
              ValueName = 'NoDataExecutionPrevention'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
         {
              ValueName = 'NoHeapTerminationOnCorruption'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
         {
              ValueName = 'NoBackgroundPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
         {
              ValueName = 'NoGPOListChanges'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
         {
              ValueName = 'AlwaysInstallElevated'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
         {
              ValueName = 'EnableUserControl'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
         {
              ValueName = 'DeviceEnumerationPolicy'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
         {
              ValueName = 'AllowInsecureGuestAuth'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON'
         {
              ValueName = '\\*\NETLOGON'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\SYSVOL'
         {
              ValueName = '\\*\SYSVOL'
              ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
         {
              ValueName = 'NoLockScreenCamera'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
         {
              ValueName = 'NoLockScreenSlideshow'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
         {
              ValueName = 'EnableScriptBlockLogging'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
         {
              ValueName = 'EnableScriptBlockInvocationLogging'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Safer\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Safer'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\a9e18c21-ff8f-43cf-b9fc-db40eed693ba\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Appx\a9e18c21-ff8f-43cf-b9fc-db40eed693ba'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Dll'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\EnforcementMode'
         {
              ValueName = 'EnforcementMode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\5e3ec135-b5af-4961-ae4d-cde98710afc9\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePublisherRule Id="5e3ec135-b5af-4961-ae4d-cde98710afc9" Name="Block Google Chrome" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=GOOGLE INC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US" ProductName="GOOGLE CHROME" BinaryName="CHROME.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\5e3ec135-b5af-4961-ae4d-cde98710afc9'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\6db6c8f3-cf7c-4754-a438-94c95345bb53\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePublisherRule Id="6db6c8f3-cf7c-4754-a438-94c95345bb53" Name="Block Mozilla Firefox" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CA, C=US" ProductName="FIREFOX" BinaryName="FIREFOX.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\6db6c8f3-cf7c-4754-a438-94c95345bb53'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\881d54fe-3848-4d6a-95fd-42d48ebe60b8\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePublisherRule Id="881d54fe-3848-4d6a-95fd-42d48ebe60b8" Name="Block Internet Explorer" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="IEXPLORE.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\881d54fe-3848-4d6a-95fd-42d48ebe60b8'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\921cc481-6e17-4653-8f75-050b80acca20\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\921cc481-6e17-4653-8f75-050b80acca20'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\a61c8b2c-a319-4cd0-9690-d2177cad7b51\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\a61c8b2c-a319-4cd0-9690-d2177cad7b51'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\fd686d83-a829-4351-8ff4-27c7de5755d2\Value'
         {
              ValueName = 'Value'
              ValueData = '<FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\fd686d83-a829-4351-8ff4-27c7de5755d2'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Msi'
         }

         <#
         	This MultiString Value has a value of $null, 
          	Some Security Policies require Registry Values to be $null
          	If you believe ' ' is the correct value for this string, you may change it here.
         #>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script\'
         {
              ValueName = ''
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Script'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
         {
              ValueName = 'EnableSmartScreen'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
         {
              ValueName = 'ShellSmartScreenLevel'
              ValueData = 'Block'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\System'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
         {
              ValueName = 'AllowIndexingEncryptedStoresOrItems'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
         {
              ValueName = 'AllowDigest'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
         {
              ValueName = 'AllowBasic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
         {
              ValueName = 'AllowUnencryptedTraffic'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
         {
              ValueName = 'DisableRunAs'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
         {
              ValueName = 'DisablePasswordSaving'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
         {
              ValueName = 'fDisableCdm'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
         {
              ValueName = 'fPromptForPassword'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
         {
              ValueName = 'fEncryptRPCTraffic'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
         {
              ValueName = 'MinEncryptionLevel'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PolicyVersion'
         {
              ValueName = 'PolicyVersion'
              ValueData = 538
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
         {
              ValueName = 'EnableFirewall'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
         {
              ValueName = 'DefaultOutboundAction'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
         {
              ValueName = 'DefaultInboundAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
         {
              ValueName = 'AllowWindowsInkWorkspace'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
         {
              ValueName = 'UseLogonCredential'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
         {
              ValueName = 'DisableExceptionChainValidation'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
         {
              ValueName = 'DriverLoadPolicy'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
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

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
         {
              ValueName = 'LdapEnforceChannelBinding'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
         {
              ValueName = 'EnableICMPRedirect'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
         {
              ValueName = 'DisableIPSourceRouting'
              ValueData = 2
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

         AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
         {
              Name = 'Computer Account Management'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
         {
              Name = 'Computer Account Management'
              Ensure = 'Absent'
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

         AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
         {
              Name = 'Directory Service Access'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
         {
              Name = 'Directory Service Access'
              Ensure = 'Present'
              AuditFlag = 'Failure'
         }

         AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
         {
              Name = 'Directory Service Changes'
              Ensure = 'Present'
              AuditFlag = 'Success'
         }

          AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
         {
              Name = 'Directory Service Changes'
              Ensure = 'Present'
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

         Service 'Services(INF): AppIDSvc'
         {
              Name = 'AppIDSvc'
              State = 'Running'
         }

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

         SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         {
              System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
              Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
         {
              Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
              Name = 'Domain_controller_LDAP_server_signing_requirements'
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

         SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
         {
              Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
              User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
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

         SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
         {
              Name = 'Domain_controller_Refuse_machine_account_password_changes'
              Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
         }

         SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
         {
              Name = 'Network_security_LDAP_client_signing_requirements'
              Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
         }

         SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
         {
              Name = 'Domain_member_Maximum_machine_account_password_age'
              Domain_member_Maximum_machine_account_password_age = '30'
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

         UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
         {
              Policy = 'Debug_programs'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
         {
              Policy = 'Force_shutdown_from_a_remote_system'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
         {
              Policy = 'Lock_pages_in_memory'
              Force = $True
              Identity = @('')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
         {
              Policy = 'Access_Credential_Manager_as_a_trusted_caller'
              Force = $True
              Identity = @('')
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

         UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
         {
              Policy = 'Impersonate_a_client_after_authentication'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-6', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
         {
              Policy = 'Create_a_pagefile'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
         {
              Policy = 'Allow_log_on_through_Remote_Desktop_Services'
              Force = $True
              Identity = @('*S-1-5-32-544')
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

         UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
         {
              Policy = 'Profile_single_process'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
         {
              Policy = 'Create_global_objects'
              Force = $True
              Identity = @('*S-1-5-20', '*S-1-5-19', '*S-1-5-6', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
         {
              Policy = 'Act_as_part_of_the_operating_system'
              Force = $True
              Identity = @('')
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
              Identity = @('*S-1-5-9', '*S-1-5-11', '*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
         {
              Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
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

         UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
         {
              Policy = 'Allow_log_on_locally'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
         {
              Policy = 'Perform_volume_maintenance_tasks'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
         {
              Policy = 'Modify_firmware_environment_values'
              Force = $True
              Identity = @('*S-1-5-32-544')
         }

         SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
         {
              Name = 'Network_access_Allow_anonymous_SID_Name_translation'
              Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
