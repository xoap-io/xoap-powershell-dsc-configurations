Configuration 'DoD_Google_Chrome_STIG_Computer_v3r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'DoD_Google_Chrome_STIG_Computer_v3r1'
    {
        RegistryPolicyFile 'Chrome_SafeBrowsingEnabled'
        {
            ValueName  = 'SafeBrowsingEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_SafeBrowsingExtendedReportingEnabled'
        {
            ValueName  = 'SafeBrowsingExtendedReportingEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_PasswordManagerEnabled'
        {
            ValueName  = 'PasswordManagerEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_ExtensionInstallBlocklist'
        {
            ValueName  = '1'
            ValueData  = '*'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist'
        }

        RegistryPolicyFile 'Chrome_SitePerProcess'
        {
            ValueName  = 'SitePerProcess'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_SSLVersionMin'
        {
            ValueName  = 'SSLVersionMin'
            ValueData  = 'tls1.2'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_AutofillAddressEnabled'
        {
            ValueName  = 'AutofillAddressEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_AutofillCreditCardEnabled'
        {
            ValueName  = 'AutofillCreditCardEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RegistryPolicyFile 'Chrome_MetricsReportingEnabled'
        {
            ValueName  = 'MetricsReportingEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        # v3r1 New: Enforce Safe Browsing Level 2 (enhanced)
        RegistryPolicyFile 'Chrome_SafeBrowsingProtectionLevel'
        {
            ValueName  = 'SafeBrowsingProtectionLevel'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_Google_Chrome_STIG_Computer_v3r1 -OutputPath 'C:\DSC\DoD_Google_Chrome_STIG_Computer_v3r1'
