
Configuration 'MSTF_SecurityBaseline_M365_Apps_v2206_Legacy_JScript_Block_Computer'
{
     Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
     Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
     Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
     Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

     Node 'MSTF_SecurityBaseline_M365_Apps_v2206_Legacy_JScript_Block_Computer'
     {

        # Blocks legacy JScript execution in Excel
        RegistryPolicyFile 'excel.exe'
        {
            ValueName = 'excel.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in Publisher
        RegistryPolicyFile 'mspub.exe'
        {
            ValueName = 'mspub.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in PowerPoint
        RegistryPolicyFile 'powerpnt.exe'
        {
            ValueName = 'powerpnt.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in OneNote
        RegistryPolicyFile 'onenote.exe'
        {
            ValueName = 'onenote.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in Visio
        RegistryPolicyFile 'visio.exe'
        {
            ValueName = 'visio.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in Project
        RegistryPolicyFile 'winproj.exe'
        {
            ValueName = 'winproj.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in Word
        RegistryPolicyFile 'winword.exe'
        {
            ValueName = 'winword.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in Outlook
        RegistryPolicyFile 'outlook.exe'
        {
            ValueName = 'outlook.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

        # Blocks legacy JScript execution in Access
        RegistryPolicyFile 'msaccess.exe'
        {
            ValueName = 'msaccess.exe'
            ValueData = 69632
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key = 'HKLM:\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE'
        }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
