# DSC Configuration: XOAP_Debloat_W10_Privacy
# Purpose: Disables machine-wide telemetry, diagnostic data collection, advertising ID, and error reporting for Windows 10.
Configuration 'XOAP_Debloat_W10_Privacy'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Debloat_W10_Privacy'
    {
        # --- Telemetry & Diagnostic Data ---
        Registry 'Telemetry_AllowTelemetry'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure    = 'Present'
            ValueName = 'AllowTelemetry'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Telemetry_DisableOneSettings'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure    = 'Present'
            ValueName = 'DisableOneSettingsDownloads'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Telemetry_NoFeedbackNotifications'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure    = 'Present'
            ValueName = 'DoNotShowFeedbackNotifications'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Telemetry_CEIPDisable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
            Ensure    = 'Present'
            ValueName = 'CEIPEnable'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Telemetry_AppCompatDisable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            Ensure    = 'Present'
            ValueName = 'AITEnable'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Telemetry_PCANotifyDisable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            Ensure    = 'Present'
            ValueName = 'DisablePCANotify'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Advertising_DisableID'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
            Ensure    = 'Present'
            ValueName = 'DisabledByGroupPolicy'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'ErrorReporting_Disable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
            Ensure    = 'Present'
            ValueName = 'Disabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Telemetry Services ---
        Service 'DiagTrack_Disable'
        {
            Name        = 'DiagTrack'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'dmwappushsvc_Disable'
        {
            Name        = 'dmwappushsvc'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }
    }
}
XOAP_Debloat_W10_Privacy -OutputPath 'C:\DSC\XOAP_Debloat_W10_Privacy'
