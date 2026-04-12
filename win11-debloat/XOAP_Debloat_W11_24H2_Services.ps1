# DSC Configuration: XOAP_Debloat_W11_24H2_Services
# Purpose: Disables Xbox gaming services, retail/wallet/phone services, and telemetry scheduled tasks for Windows 11 24H2.
Configuration 'XOAP_Debloat_W11_24H2_Services'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Debloat_W11_24H2_Services'
    {
        # --- Xbox Services ---
        Service 'Xbox_AuthManager'
        {
            Name        = 'XblAuthManager'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'Xbox_GameSave'
        {
            Name        = 'XblGameSave'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'Xbox_NetApiSvc'
        {
            Name        = 'XboxNetApiSvc'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'Xbox_GipSvc'
        {
            Name        = 'XboxGipSvc'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'BcastDVR'
        {
            Name        = 'BcastDVRUserService'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        # --- Unnecessary Background Services ---
        Service 'RetailDemo'
        {
            Name        = 'RetailDemo'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'WalletService'
        {
            Name        = 'WalletService'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        Service 'PhoneSvc'
        {
            Name        = 'PhoneSvc'
            State       = 'Stopped'
            StartupType = 'Disabled'
        }

        # --- Telemetry Scheduled Tasks ---
        ScheduledTask 'Task_CompatibilityAppraiser'
        {
            TaskName = 'Microsoft Compatibility Appraiser'
            TaskPath = '\Microsoft\Windows\Application Experience\'
            Enable   = $false
        }

        ScheduledTask 'Task_ProgramDataUpdater'
        {
            TaskName = 'ProgramDataUpdater'
            TaskPath = '\Microsoft\Windows\Application Experience\'
            Enable   = $false
        }

        ScheduledTask 'Task_StartupAppTask'
        {
            TaskName = 'StartupAppTask'
            TaskPath = '\Microsoft\Windows\Application Experience\'
            Enable   = $false
        }

        ScheduledTask 'Task_DeviceInfo'
        {
            TaskName = 'Device'
            TaskPath = '\Microsoft\Windows\Device Information\'
            Enable   = $false
        }
    }
}
XOAP_Debloat_W11_24H2_Services -OutputPath 'C:\DSC\XOAP_Debloat_W11_24H2_Services'
