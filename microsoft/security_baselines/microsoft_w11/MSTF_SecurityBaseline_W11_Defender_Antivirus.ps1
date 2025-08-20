
Configuration 'MSTF_SecurityBaseline_W11_22H2_Defender_Antivirus'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_W11_22H2_Defender_Antivirus'
     {
         # Enables protection against potentially unwanted applications (PUA)
         RegistryPolicyFile 'PUAProtection'
         {
             ValueName = 'PUAProtection'
             ValueData = 1
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
         }

         # Sets cloud protection level to high for Defender
         RegistryPolicyFile 'MpCloudBlockLevel'
         {
             ValueName = 'MpCloudBlockLevel'
             ValueData = 2
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine'
         }

         # Enables IOAV protection (scans files from the web)
         RegistryPolicyFile 'DisableIOAVProtection'
         {
             ValueName = 'DisableIOAVProtection'
             ValueData = 0
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         # Enables real-time monitoring for Defender
         RegistryPolicyFile 'DisableRealtimeMonitoring'
         {
             ValueName = 'DisableRealtimeMonitoring'
             ValueData = 0
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         # Enables script scanning for Defender
         RegistryPolicyFile 'DisableScriptScanning'
         {
             ValueName = 'DisableScriptScanning'
             ValueData = 0
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'
         }

         # Enables scanning of removable drives
         RegistryPolicyFile 'DisableRemovableDriveScanning'
         {
             ValueName = 'DisableRemovableDriveScanning'
             ValueData = 0
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Scan'
         }

         # Allows Defender to submit samples to Microsoft for analysis
         RegistryPolicyFile 'SubmitSamplesConsent'
         {
             ValueName = 'SubmitSamplesConsent'
             ValueData = 1
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         # Enables advanced reporting to Microsoft for Defender
         RegistryPolicyFile 'SpynetReporting'
         {
             ValueName = 'SpynetReporting'
             ValueData = 2
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         # Enables blocking of files at first sight
         RegistryPolicyFile 'DisableBlockAtFirstSeen'
         {
             ValueName = 'DisableBlockAtFirstSeen'
             ValueData = 0
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet'
         }

         # Enables Attack Surface Reduction (ASR) rules
         RegistryPolicyFile 'ExploitGuard_ASR_Rules'
         {
             ValueName = 'ExploitGuard_ASR_Rules'
             ValueData = 1
             ValueType = 'Dword'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
         }

         # Enables ASR rule: Block credential stealing from LSASS
         RegistryPolicyFile '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
         {
             ValueName = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from browsers
         RegistryPolicyFile '3b576869-a4ec-4529-8536-b80a7769e899'
         {
             ValueName = '3b576869-a4ec-4529-8536-b80a7769e899'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from Office apps
         RegistryPolicyFile 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
         {
             ValueName = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from Winlogon
         RegistryPolicyFile '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
         {
             ValueName = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from PowerShell
         RegistryPolicyFile '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
         {
             ValueName = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from scripting engines
         RegistryPolicyFile 'd3e037e1-3eb8-44c8-a917-57927947596d'
         {
             ValueName = 'd3e037e1-3eb8-44c8-a917-57927947596d'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from unknown sources
         RegistryPolicyFile 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
         {
             ValueName = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from legacy apps
         RegistryPolicyFile '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
         {
             ValueName = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from custom scripts
         RegistryPolicyFile 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
         {
             ValueName = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from system processes
         RegistryPolicyFile '26190899-1602-49e8-8b27-eb1d0a1ce869'
         {
             ValueName = '26190899-1602-49e8-8b27-eb1d0a1ce869'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from network processes
         RegistryPolicyFile '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
         {
             ValueName = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from device drivers
         RegistryPolicyFile 'c1db55ab-c21a-4637-bb3f-a12568109d35'
         {
             ValueName = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables ASR rule: Block credential stealing from unknown drivers
         RegistryPolicyFile 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
         {
             ValueName = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
             ValueData = '1'
             ValueType = 'String'
             TargetType = 'ComputerConfiguration'
             Key = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
         }

         # Enables network protection to block suspicious outbound traffic
         RegistryPolicyFile 'EnableNetworkProtection'
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
