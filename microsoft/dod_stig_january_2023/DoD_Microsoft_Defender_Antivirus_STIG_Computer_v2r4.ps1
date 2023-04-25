
Configuration DoD_Microsoft_Defender_Antivirus_STIG_Computer_v2r4
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node DoD_Microsoft_Defender_Antivirus_STIG_Computer_v2r4
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
         {
              ValueName = 'PUAProtection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions'
         {
              ValueName = 'DisableAutoExclusions'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
         {
              ValueName = 'DisableRemovableDriveScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
         {
              ValueName = 'DisableEmailScanning'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\ScheduleDay'
         {
              ValueName = 'ScheduleDay'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
         {
              ValueName = 'ASSignatureDue'
              ValueData = 7
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\AVSignatureDue'
         {
              ValueName = 'AVSignatureDue'
              ValueData = 7
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ScheduleDay'
         {
              ValueName = 'ScheduleDay'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
         {
              ValueName = 'DisableBlockAtFirstSeen'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
         {
              ValueName = 'SpynetReporting'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
         {
              ValueName = 'SubmitSamplesConsent'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\Threats_ThreatSeverityDefaultAction'
         {
              ValueName = 'Threats_ThreatSeverityDefaultAction'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\5'
         {
              ValueName = '5'
              ValueData = '2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\4'
         {
              ValueName = '4'
              ValueData = '2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\2'
         {
              ValueName = '2'
              ValueData = '2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\1'
         {
              ValueName = '1'
              ValueData = '2'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
         {
              ValueName = 'ExploitGuard_ASR_Rules'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
         {
              ValueName = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
         {
              ValueName = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3B576869-A4EC-4529-8536-B80A7769E899'
         {
              ValueName = '3B576869-A4EC-4529-8536-B80A7769E899'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
         {
              ValueName = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D3E037E1-3EB8-44C8-A917-57927947596D'
         {
              ValueName = 'D3E037E1-3EB8-44C8-A917-57927947596D'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
         {
              ValueName = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
         {
              ValueName = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
              ValueData = '1'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
         {
              ValueName = 'EnableNetworkProtection'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
