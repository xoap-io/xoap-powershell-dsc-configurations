# DSC Configuration: XOAP_MDE_Onboarding
# Purpose: Configures Microsoft Defender for Endpoint service prerequisites and connectivity settings.
# NOTE: Actual tenant onboarding requires running the org-specific onboarding package from the MDE portal.
Configuration 'XOAP_MDE_Onboarding'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_MDE_Onboarding'
    {
        # --- Services: Microsoft Defender for Endpoint ---
        Service 'Sense'
        {
            Name        = 'Sense'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'WinDefend'
        {
            Name        = 'WinDefend'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'MdCoreSvc'
        {
            Name        = 'MdCoreSvc'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Registry: MDE Connectivity & Sample Collection ---
        Registry 'MDE_AllowSampleCollection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
            Ensure    = 'Present'
            ValueName = 'AllowSampleCollection'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'MDE_EnablePassiveMode'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
            Ensure    = 'Present'
            ValueName = 'PassiveMode'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: Defender Real-Time Protection (required for MDE) ---
        Registry 'Defender_EnableRealtime'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            Ensure    = 'Present'
            ValueName = 'DisableRealtimeMonitoring'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Defender_EnableBehaviorMonitoring'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
            Ensure    = 'Present'
            ValueName = 'DisableBehaviorMonitoring'
            ValueType = 'Dword'
            ValueData = '0'
        }

        # --- Registry: TLS 1.2 for MDE cloud connectivity ---
        Registry 'TLS12_Client_Enabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_MDE_Onboarding -OutputPath 'C:\DSC\XOAP_MDE_Onboarding'
