Configuration 'DoD_Mozilla_Firefox_STIG_Computer_v6r6'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'DoD_Mozilla_Firefox_STIG_Computer_v6r6'
    {
        RegistryPolicyFile 'FF_DisablePasswordManager'
        {
            ValueName  = 'OfferToSaveLogins'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
        }

        RegistryPolicyFile 'FF_BlockAboutConfig'
        {
            ValueName  = 'BlockAboutConfig'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
        }

        RegistryPolicyFile 'FF_DisablePrivateBrowsing'
        {
            ValueName  = 'DisablePrivateBrowsing'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
        }

        RegistryPolicyFile 'FF_DisableTelemetry'
        {
            ValueName  = 'DisableTelemetry'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
        }

        RegistryPolicyFile 'FF_SSLVersionMin'
        {
            ValueName  = 'SSLVersionMin'
            ValueData  = 'tls1.2'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SSLVersionMin'
        }

        RegistryPolicyFile 'FF_ExtensionBlocklist'
        {
            ValueName  = 'ExtensionBlocklist'
            ValueData  = '*'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\ExtensionBlocklist'
        }

        RegistryPolicyFile 'FF_DisableFormHistory'
        {
            ValueName  = 'DisableFormHistory'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
        }

        RegistryPolicyFile 'FF_EnableTrackingProtection'
        {
            ValueName  = 'Value'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_Mozilla_Firefox_STIG_Computer_v6r6 -OutputPath 'C:\DSC\DoD_Mozilla_Firefox_STIG_Computer_v6r6'
