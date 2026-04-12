# DSC Configuration: XOAP_AzureArc_ConnectedMachine
# Purpose: Configures Azure Arc Connected Machine agent prerequisites and service baseline.
Configuration 'XOAP_AzureArc_ConnectedMachine'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_AzureArc_ConnectedMachine'
    {
        # --- Services: Azure Arc Agent ---
        Service 'himds'
        {
            Name        = 'himds'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'GCArcService'
        {
            Name        = 'GCArcService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'ExtensionService'
        {
            Name        = 'ExtensionService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- File: Arc Agent Data Directory ---
        File 'ArcDataDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\AzureConnectedMachineAgent'
        }

        File 'ArcLogDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\AzureConnectedMachineAgent\Logs'
        }

        # --- Registry: Arc Agent Configuration ---
        Registry 'Arc_TelemetryEnabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure Connected Machine Agent'
            Ensure    = 'Present'
            ValueName = 'TelemetryEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Arc_UpdateServiceEnabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure Connected Machine Agent'
            Ensure    = 'Present'
            ValueName = 'AutoUpdateEnabled'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Registry: TLS 1.2 minimum for Arc connectivity ---
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
XOAP_AzureArc_ConnectedMachine -OutputPath 'C:\DSC\XOAP_AzureArc_ConnectedMachine'
