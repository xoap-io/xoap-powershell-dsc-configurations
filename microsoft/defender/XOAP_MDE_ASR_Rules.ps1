# DSC Configuration: XOAP_MDE_ASR_Rules
# Purpose: Configures Microsoft Defender for Endpoint Attack Surface Reduction (ASR) rules.
# Rule values: 1 = Block, 2 = Audit, 0 = Disabled
Configuration 'XOAP_MDE_ASR_Rules'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node 'XOAP_MDE_ASR_Rules'
    {
        # --- ASR: Block executable content from email and webmail ---
        Registry 'ASR_BlockEmailExecutable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block Office apps from creating child processes ---
        Registry 'ASR_BlockOfficeChildProcess'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block Office apps from creating executable content ---
        Registry 'ASR_BlockOfficeExecutableContent'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = '3b576869-a4ec-4529-8536-b80a7769e899'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block Office apps from injecting into other processes ---
        Registry 'ASR_BlockOfficeInjection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block JavaScript/VBScript from launching downloaded executables ---
        Registry 'ASR_BlockScriptDownloadedExecutable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'd3e037e1-3eb8-44c8-a917-57927947596d'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block execution of potentially obfuscated scripts ---
        Registry 'ASR_BlockObfuscatedScripts'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block Win32 API calls from Office macros ---
        Registry 'ASR_BlockOfficeWin32API'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block credential stealing from lsass.exe ---
        Registry 'ASR_BlockLSASS'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block process creations from PSExec/WMI ---
        Registry 'ASR_BlockPSExecWMI'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
            ValueType = 'String'
            ValueData = '2'
        }

        # --- ASR: Block untrusted/unsigned processes from USB ---
        Registry 'ASR_BlockUnsignedUSB'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Block persistence through WMI event subscription ---
        Registry 'ASR_BlockWMIPersistence'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Use advanced protection against ransomware ---
        Registry 'ASR_AdvancedRansomwareProtection'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            Ensure    = 'Present'
            ValueName = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
            ValueType = 'String'
            ValueData = '1'
        }

        # --- ASR: Enable ASR ---
        Registry 'ASR_EnableExploitGuard'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            Ensure    = 'Present'
            ValueName = 'ExploitGuard_ASR_Rules'
            ValueType = 'Dword'
            ValueData = '1'
        }
    }
}
XOAP_MDE_ASR_Rules -OutputPath 'C:\DSC\XOAP_MDE_ASR_Rules'
