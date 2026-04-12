# DSC Configuration: XOAP_Citrix_Session_Recording_Agent_W2K19
# Purpose: Configures Citrix Session Recording Agent on Windows Server 2019 session hosts.
Configuration 'XOAP_Citrix_Session_Recording_Agent_W2K19'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_Citrix_Session_Recording_Agent_W2K19'
    {
        # --- Service: Session Recording Agent ---
        Service 'SrAgentService'
        {
            Name        = 'SrAgent'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- File: Session Recording Storage ---
        File 'SrStorageDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\SessionRecordings'
        }

        File 'SrLogDir'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'C:\ProgramData\Citrix\SessionRecording\Agent\Logs'
        }

        # --- Registry: Session Recording Agent Configuration ---
        Registry 'SrAgent_EnableRecording'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\SmartAuditor\Agent'
            Ensure    = 'Present'
            ValueName = 'EnableSessionRecording'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'SrAgent_RecordingMode'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\SmartAuditor\Agent'
            Ensure    = 'Present'
            ValueName = 'SmAudRecordingMode'
            ValueType = 'Dword'
            ValueData = '2'
        }

        Registry 'SrAgent_ServerPort'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\SmartAuditor\Agent'
            Ensure    = 'Present'
            ValueName = 'SmAudRecorderAcsPort'
            ValueType = 'Dword'
            ValueData = '1801'
        }

        Registry 'SrAgent_StoragePath'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\SmartAuditor\Agent'
            Ensure    = 'Present'
            ValueName = 'SmAudRecordingPath'
            ValueType = 'String'
            ValueData = 'C:\SessionRecordings'
        }

        Registry 'SrAgent_LoggingEnabled'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\SmartAuditor\Agent'
            Ensure    = 'Present'
            ValueName = 'EnableLogging'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_Citrix_Session_Recording_Agent_W2K19 -OutputPath 'C:\DSC\XOAP_Citrix_Session_Recording_Agent_W2K19'
