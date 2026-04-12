Configuration 'DoD_Microsoft_Defender_Antivirus_STIG_Computer_v3r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'DoD_Microsoft_Defender_Antivirus_STIG_Computer_v3r1'
    {
        RegistryPolicyFile 'MDAV_DisableAntiSpyware'
        {
            ValueName  = 'DisableAntiSpyware'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'MDAV_DisableRealtimeMonitoring'
        {
            ValueName  = 'DisableRealtimeMonitoring'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'MDAV_DisableBehaviorMonitoring'
        {
            ValueName  = 'DisableBehaviorMonitoring'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        }

        RegistryPolicyFile 'MDAV_SpynetReporting'
        {
            ValueName  = 'SpynetReporting'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }

        RegistryPolicyFile 'MDAV_SubmitSamplesConsent'
        {
            ValueName  = 'SubmitSamplesConsent'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        }

        RegistryPolicyFile 'MDAV_PUAProtection'
        {
            ValueName  = 'PUAProtection'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'MDAV_CloudBlockLevel'
        {
            ValueName  = 'MpCloudBlockLevel'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        }

        RegistryPolicyFile 'MDAV_EnableNetworkProtection'
        {
            ValueName  = 'EnableNetworkProtection'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        }

        RegistryPolicyFile 'MDAV_TamperProtection'
        {
            ValueName  = 'TamperProtection'
            ValueData  = 5
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        }

        RegistryPolicyFile 'MDAV_DisableLocalAdminMerge'
        {
            ValueName  = 'DisableLocalAdminMerge'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        }

        RegistryPolicyFile 'MDAV_EnableControlledFolderAccess'
        {
            ValueName  = 'EnableControlledFolderAccess'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_Microsoft_Defender_Antivirus_STIG_Computer_v3r1 -OutputPath 'C:\DSC\DoD_Microsoft_Defender_Antivirus_STIG_Computer_v3r1'
