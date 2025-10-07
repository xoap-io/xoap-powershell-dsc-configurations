
Configuration 'MSTF_SecurityBaseline_W10_1607_Defender'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'MSTF_SecurityBaseline_W10_1607_Defender'
	{
          # Disable Windows Defender AntiSpyware
          RegistryPolicyFile 'DisableAntiSpyware'
          {
               ValueName = 'DisableAntiSpyware'
               ValueData = 0
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
          }

          # Enable Real-Time Protection Behavior Monitoring
          RegistryPolicyFile 'DisableBehaviorMonitoring'
          {
               ValueName = 'DisableBehaviorMonitoring'
               ValueData = 0
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
          }

          # Enable scanning of removable drives
          RegistryPolicyFile 'DisableRemovableDriveScanning'
          {
               ValueName = 'DisableRemovableDriveScanning'
               ValueData = 0
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
          }

          # Enable email scanning
          RegistryPolicyFile 'DisableEmailScanning'
          {
               ValueName = 'DisableEmailScanning'
               ValueData = 0
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
          }

          # Disable local override for Spynet reporting
          RegistryPolicyFile 'LocalSettingOverrideSpynetReporting'
          {
               ValueName = 'LocalSettingOverrideSpynetReporting'
               ValueData = 0
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
          }

          # Set Spynet sample submission consent
          RegistryPolicyFile 'SubmitSamplesConsent'
          {
               ValueName = 'SubmitSamplesConsent'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
          }

          # Set Spynet reporting level
          RegistryPolicyFile 'SpynetReporting'
          {
               ValueName = 'SpynetReporting'
               ValueData = 2
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
          }

          # Refresh registry policy to apply changes
          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
               IsSingleInstance = 'Yes'
          }
     }
}
