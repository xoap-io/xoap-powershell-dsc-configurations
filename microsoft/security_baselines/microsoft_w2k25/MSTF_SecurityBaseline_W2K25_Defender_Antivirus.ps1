# DSC Configuration: MSTF_SecurityBaseline_W2K25_Defender_Antivirus
# Purpose: Applies Microsoft Security Baseline Defender Antivirus policies for Windows Server 2025.
Configuration 'MSTF_SecurityBaseline_W2K25_Defender_Antivirus'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'  -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_W2K25_Defender_Antivirus'
    {
        RegistryPolicyFile 'Defender_PUAProtection'
        {
            ValueName  = 'PUAProtection'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'Defender_DisableRealtimeMonitoring'
        {
            ValueName  = 'DisableRealtimeMonitoring'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'Defender_DisableBehaviorMonitoring'
        {
            ValueName  = 'DisableBehaviorMonitoring'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'Defender_SpynetReporting'
        {
            ValueName  = 'SpynetReporting'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }

        RegistryPolicyFile 'Defender_SubmitSamplesConsent'
        {
            ValueName  = 'SubmitSamplesConsent'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }

        RegistryPolicyFile 'Defender_MpCloudBlockLevel'
        {
            ValueName  = 'MpCloudBlockLevel'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        }

        RegistryPolicyFile 'Defender_CloudExtendedTimeout'
        {
            ValueName  = 'MpBafsExtendedTimeout'
            ValueData  = 20
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        }

        RegistryPolicyFile 'Defender_EnableNetworkProtection'
        {
            ValueName  = 'EnableNetworkProtection'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        }

        RegistryPolicyFile 'Defender_EnableControlledFolderAccess'
        {
            ValueName  = 'EnableControlledFolderAccess'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        }

        RegistryPolicyFile 'Defender_TamperProtection'
        {
            ValueName  = 'TamperProtection'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'Defender_DisableLocalAdminMerge'
        {
            ValueName  = 'DisableLocalAdminMerge'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_W2K25_Defender_Antivirus -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W2K25_Defender_Antivirus'
