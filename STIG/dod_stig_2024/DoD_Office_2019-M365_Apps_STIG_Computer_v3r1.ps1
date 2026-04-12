Configuration 'DoD_Office_2019-M365_Apps_STIG_Computer_v3r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'DoD_Office_2019-M365_Apps_STIG_Computer_v3r1'
    {
        RegistryPolicyFile 'O365_Word_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
        }

        RegistryPolicyFile 'O365_Excel_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security'
        }

        RegistryPolicyFile 'O365_PowerPoint_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\PowerPoint\Security'
        }

        RegistryPolicyFile 'O365_Outlook_VBAWarnings'
        {
            ValueName  = 'VBAWarnings'
            ValueData  = 4
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security'
        }

        RegistryPolicyFile 'O365_DisableAllActiveX'
        {
            ValueName  = 'DisableAllActiveX'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\Common\Security'
        }

        RegistryPolicyFile 'O365_Excel_DisableDDE'
        {
            ValueName  = 'DisableDDE'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Options'
        }

        RegistryPolicyFile 'O365_DisableTelemetry'
        {
            ValueName  = 'sendtelemetry'
            ValueData  = 3
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\Common\ClientTelemetry'
        }

        RegistryPolicyFile 'O365_AutomaticUpdates'
        {
            ValueName  = 'enableautomaticupdates'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
        }

        # v3r1 New: Block macros from internet-sourced files
        RegistryPolicyFile 'O365_Word_BlockMacrosInternet'
        {
            ValueName  = 'blockcontentexecutionfrominternet'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
        }

        RegistryPolicyFile 'O365_Excel_BlockMacrosInternet'
        {
            ValueName  = 'blockcontentexecutionfrominternet'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security'
        }

        RegistryPolicyFile 'O365_PowerPoint_BlockMacrosInternet'
        {
            ValueName  = 'blockcontentexecutionfrominternet'
            ValueData  = 1
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\PowerPoint\Security'
        }

        RefreshRegistryPolicy 'ActivateClientSideExtension'
        {
            IsSingleInstance = 'Yes'
        }
    }
}
DoD_Office_2019-M365_Apps_STIG_Computer_v3r1 -OutputPath 'C:\DSC\DoD_Office_2019-M365_Apps_STIG_Computer_v3r1'
