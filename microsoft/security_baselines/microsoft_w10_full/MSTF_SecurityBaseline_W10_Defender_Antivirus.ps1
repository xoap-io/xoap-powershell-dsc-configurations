# DSC Configuration: MSTF_SecurityBaseline_W10_Defender_Antivirus
# Purpose: Applies Windows Defender Antivirus baseline policies for Windows 10.
Configuration 'MSTF_SecurityBaseline_W10_Defender_Antivirus'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W10_Defender_Antivirus'
    {
        RegistryPolicyFile 'PUAProtection'
        {
            ValueName  = 'PUAProtection'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'DisableAntiSpyware'
        {
            ValueName  = 'DisableAntiSpyware'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'DisableRealtimeMonitoring'
        {
            ValueName  = 'DisableRealtimeMonitoring'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'DisableBehaviorMonitoring'
        {
            ValueName  = 'DisableBehaviorMonitoring'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'DisableOnAccessProtection'
        {
            ValueName  = 'DisableOnAccessProtection'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'DisableScanOnRealtimeEnable'
        {
            ValueName  = 'DisableScanOnRealtimeEnable'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'DisableIOAVProtection'
        {
            ValueName  = 'DisableIOAVProtection'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'SpynetReporting'
        {
            ValueName  = 'SpynetReporting'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }

        RegistryPolicyFile 'SubmitSamplesConsent'
        {
            ValueName  = 'SubmitSamplesConsent'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }

        RegistryPolicyFile 'MpCloudBlockLevel'
        {
            ValueName  = 'MpCloudBlockLevel'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        }

        RegistryPolicyFile 'EnableNetworkProtection'
        {
            ValueName  = 'EnableNetworkProtection'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        }

        RegistryPolicyFile 'ExploitProtection_ASLR'
        {
            ValueName  = 'EnableSystemWideOverride'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W10_Defender_Antivirus -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W10_Defender_Antivirus'
