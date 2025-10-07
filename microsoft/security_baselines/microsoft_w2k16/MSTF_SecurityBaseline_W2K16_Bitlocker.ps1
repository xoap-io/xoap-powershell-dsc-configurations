
Configuration 'MSTF_SecurityBaseline_W10_1607_Bitlocker'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W2K16_Bitlocker'
     {
          # Configure BitLocker drive location
          RegistryPolicyFile 'FDVLocation'
          {
               ValueName = 'FDVLocation'
               ValueData = 'C:\BitLocker'
               ValueType = 'String'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Enable advanced startup for BitLocker
          RegistryPolicyFile 'UseAdvancedStartup'
          {
               ValueName = 'UseAdvancedStartup'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Allow BitLocker without TPM
          RegistryPolicyFile 'EnableBDEWithNoTPM'
          {
               ValueName = 'EnableBDEWithNoTPM'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Configure TPM usage for BitLocker
          RegistryPolicyFile 'UseTPM'
          {
               ValueName = 'UseTPM'
               ValueData = 2
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Configure TPM key usage for BitLocker
          RegistryPolicyFile 'UseTPMKey'
          {
               ValueName = 'UseTPMKey'
               ValueData = 2
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Configure TPM PIN usage for BitLocker
          RegistryPolicyFile 'UseTPMPIN'
          {
               ValueName = 'UseTPMPIN'
               ValueData = 2
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Configure TPM Key+PIN usage for BitLocker
          RegistryPolicyFile 'UseTPMKeyPIN'
          {
               ValueName = 'UseTPMKeyPIN'
               ValueData = 2
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Enable preboot input protectors on slates
          RegistryPolicyFile 'EnablePrebootInputProtectorsOnSlates'
          {
               ValueName = 'EnablePrebootInputProtectorsOnSlates'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Require additional authentication at startup
          RegistryPolicyFile 'RequireAdditionalAuthentication'
          {
               ValueName = 'RequireAdditionalAuthentication'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Disable external DMA under lock
          RegistryPolicyFile 'DisableExternalDMAUnderLock'
          {
               ValueName = 'DisableExternalDMAUnderLock'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Do not allow clear recovery password
          RegistryPolicyFile 'RDVAllowClear'
          {
               ValueName = 'RDVAllowClear'
               ValueData = 0
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Configure recovery password settings
          RegistryPolicyFile 'RDVConfigureBDE'
          {
               ValueName = 'RDVConfigureBDE'
               ValueData = 1
               ValueType = 'Dword'
               TargetType = 'ComputerConfiguration'
               Key = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
          }

          # Refresh registry policy to apply changes
          RefreshRegistryPolicy 'ActivateClientSideExtension'
          {
               IsSingleInstance = 'Yes'
          }
     }
}
