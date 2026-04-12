# DSC Configuration: MSTF_SecurityBaseline_M365Apps_v2406_Computer
# Purpose: Applies Microsoft Security Baseline for Microsoft 365 Apps v2406.
Configuration 'MSTF_SecurityBaseline_M365Apps_v2406_Computer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'MSTF_SecurityBaseline_M365Apps_v2406_Computer'
    {
        # --- VBA Macros (all Office apps) ---
        RegistryPolicyFile 'Word_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
        }

        RegistryPolicyFile 'Excel_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security'
        }

        RegistryPolicyFile 'PowerPoint_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\PowerPoint\Security'
        }

        RegistryPolicyFile 'Outlook_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security'
        }

        # --- DDE (Dynamic Data Exchange) ---
        RegistryPolicyFile 'Word_DisableDDE'
        {
            ValueName  = 'AllowDDE'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Options'
        }

        RegistryPolicyFile 'Excel_DisableDDE'
        {
            ValueName  = 'DisableDDE'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Options'
        }

        # --- Protected View ---
        RegistryPolicyFile 'Word_DisableInternetFilesInProtectedView'
        {
            ValueName  = 'DisableInternetFilesInPV'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security\ProtectedView'
        }

        RegistryPolicyFile 'Excel_DisableInternetFilesInProtectedView'
        {
            ValueName  = 'DisableInternetFilesInPV'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security\ProtectedView'
        }

        # --- Disable Add-ins ---
        RegistryPolicyFile 'Word_DisableAllAddins'
        {
            ValueName  = 'DisableAllAddins'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
        }

        # --- Telemetry ---
        RegistryPolicyFile 'DisableTelemetry'
        {
            ValueName  = 'sendtelemetry'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\Common\ClientTelemetry'
        }

        # --- Update channel ---
        RegistryPolicyFile 'UpdateBranch'
        {
            ValueName  = 'updatebranch'
            ValueData  = 'Current'
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
        }

        RegistryPolicyFile 'EnableAutomaticUpdates'
        {
            ValueName  = 'enableautomaticupdates'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
        }

        # --- Outlook: Attachment security ---
        RegistryPolicyFile 'Outlook_Level1Remove'
        {
            ValueName  = 'Level1Remove'
            ValueData  = ''
            ValueType  = 'String'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security'
        }

        RegistryPolicyFile 'Outlook_DisableAttachments'
        {
            ValueName  = 'DisableAttachments'
            ValueData  = 0
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security'
        }

        # --- ActiveX ---
        RegistryPolicyFile 'DisableAllActiveX'
        {
            ValueName  = 'DisableAllActiveX'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\Common\Security'
        }

        # --- M365 Apps v2406: Disable Office AI features ---
        RegistryPolicyFile 'M365_DisableConnectedExperiences'
        {
            ValueName  = 'DisableConnectedExperiences'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Privacy'
        }

        RegistryPolicyFile 'M365_DisableOptionalConnectedExperiences'
        {
            ValueName  = 'DisableOptionalConnectedExperiences'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Privacy'
        }

        # --- M365 Apps v2406: Copilot for Microsoft 365 ---
        RegistryPolicyFile 'M365_DisableCopilot'
        {
            ValueName  = 'DisableMicrosoftCopilot'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
MSTF_SecurityBaseline_M365Apps_v2406_Computer -OutputPath 'C:\DSC\MSTF_SecurityBaseline_M365Apps_v2406_Computer'
