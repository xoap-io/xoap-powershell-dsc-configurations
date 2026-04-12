Configuration 'DoD_Microsoft_Edge_STIG_Computer_v2r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'DoD_Microsoft_Edge_STIG_Computer_v2r1'
    {
        # EDGE-00-000001: SmartScreen must be enabled
        RegistryPolicyFile 'EDGE_SmartScreen'
        {
            ValueName  = 'SmartScreenEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000002: Prevent SmartScreen prompt override
        RegistryPolicyFile 'EDGE_SmartScreenOverride'
        {
            ValueName  = 'PreventSmartScreenPromptOverride'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000003: Prevent SmartScreen prompt override for files
        RegistryPolicyFile 'EDGE_SmartScreenOverrideFiles'
        {
            ValueName  = 'PreventSmartScreenPromptOverrideForFiles'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000004: Password manager must be disabled
        RegistryPolicyFile 'EDGE_PasswordManager'
        {
            ValueName  = 'PasswordManagerEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000005: Extensions must be blocked by default
        RegistryPolicyFile 'EDGE_ExtensionBlocklist'
        {
            ValueName  = '1'
            ValueData  = '*'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
        }

        # EDGE-00-000006: Browser sign-in must be disabled
        RegistryPolicyFile 'EDGE_BrowserSignin'
        {
            ValueName  = 'BrowserSignin'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000007: Sync must be disabled
        RegistryPolicyFile 'EDGE_SyncDisabled'
        {
            ValueName  = 'SyncDisabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000008: Autofill address must be disabled
        RegistryPolicyFile 'EDGE_AutofillAddress'
        {
            ValueName  = 'AutofillAddressEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000009: Autofill credit card must be disabled
        RegistryPolicyFile 'EDGE_AutofillCreditCard'
        {
            ValueName  = 'AutofillCreditCardEnabled'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000010: SSL minimum version TLS 1.2
        RegistryPolicyFile 'EDGE_SSLVersionMin'
        {
            ValueName  = 'SSLVersionMin'
            ValueData  = 'tls1.2'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000011: Site isolation per process
        RegistryPolicyFile 'EDGE_SitePerProcess'
        {
            ValueName  = 'SitePerProcess'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-00-000012: SmartScreen PUA protection
        RegistryPolicyFile 'EDGE_SmartScreenPUA'
        {
            ValueName  = 'SmartScreenPuaEnabled'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-v2r1 New: Enhanced Safe Browsing must be enabled
        RegistryPolicyFile 'EDGE_SafeBrowsing'
        {
            ValueName  = 'SafeBrowsingProtectionLevel'
            ValueData  = 2
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        }

        # EDGE-v2r1 New: Download restrictions
        RegistryPolicyFile 'EDGE_DownloadRestrictions'
        {
            ValueName  = 'DownloadRestrictions'
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
DoD_Microsoft_Edge_STIG_Computer_v2r1 -OutputPath 'C:\DSC\DoD_Microsoft_Edge_STIG_Computer_v2r1'
