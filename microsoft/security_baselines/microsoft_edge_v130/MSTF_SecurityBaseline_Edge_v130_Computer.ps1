# DSC Configuration: MSTF_SecurityBaseline_Edge_v130_Computer
# Purpose: Applies Microsoft Security Baseline for Microsoft Edge v130.
Configuration 'MSTF_SecurityBaseline_Edge_v130_Computer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_Edge_v130_Computer'
    {
        # --- SmartScreen ---
        RegistryPolicyFile 'SmartScreenEnabled'
        {
            ValueName  = 'SmartScreenEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        RegistryPolicyFile 'SmartScreenPuaEnabled'
        {
            ValueName  = 'SmartScreenPuaEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        RegistryPolicyFile 'PreventSmartScreenPromptOverride'
        {
            ValueName  = 'PreventSmartScreenPromptOverride'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        RegistryPolicyFile 'PreventSmartScreenPromptOverrideForFiles'
        {
            ValueName  = 'PreventSmartScreenPromptOverrideForFiles'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Extensions ---
        RegistryPolicyFile 'ExtensionInstallBlocklist'
        {
            ValueName  = '1'
            ValueData  = '*'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
        }

        # --- Password Manager ---
        RegistryPolicyFile 'PasswordManagerEnabled'
        {
            ValueName  = 'PasswordManagerEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Site isolation ---
        RegistryPolicyFile 'SitePerProcess'
        {
            ValueName  = 'SitePerProcess'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Updates ---
        RegistryPolicyFile 'UpdateDefault'
        {
            ValueName  = 'UpdateDefault'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
        }

        # --- Browser sign-in ---
        RegistryPolicyFile 'BrowserSignin'
        {
            ValueName  = 'BrowserSignin'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Safe Browsing ---
        RegistryPolicyFile 'SafeBrowsingProtectionLevel'
        {
            ValueName  = 'SafeBrowsingProtectionLevel'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Downloads ---
        RegistryPolicyFile 'DownloadRestrictions'
        {
            ValueName  = 'DownloadRestrictions'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Search Engine ---
        RegistryPolicyFile 'DefaultSearchProviderEnabled'
        {
            ValueName  = 'DefaultSearchProviderEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- SSL/TLS ---
        RegistryPolicyFile 'CertificateTransparencyEnforcementDisabledForUrls'
        {
            ValueName  = 'SSLVersionMin'
            ValueData  = 'tls1.2'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Autofill ---
        RegistryPolicyFile 'AutofillAddressEnabled'
        {
            ValueName  = 'AutofillAddressEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        RegistryPolicyFile 'AutofillCreditCardEnabled'
        {
            ValueName  = 'AutofillCreditCardEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # --- Sync ---
        RegistryPolicyFile 'SyncDisabled'
        {
            ValueName  = 'SyncDisabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_Edge_v130_Computer -OutputPath 'C:\DSC\MSTF_SecurityBaseline_Edge_v130_Computer'
