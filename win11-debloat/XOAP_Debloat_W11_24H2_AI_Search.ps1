# DSC Configuration: XOAP_Debloat_W11_24H2_AI_Search
# Purpose: Disables AI features (Copilot, Recall, AI data analysis) and Bing/Cortana search integration for Windows 11 24H2.
Configuration 'XOAP_Debloat_W11_24H2_AI_Search'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node 'XOAP_Debloat_W11_24H2_AI_Search'
    {
        # --- Copilot ---
        Registry 'Copilot_Disable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
            Ensure    = 'Present'
            ValueName = 'TurnOffWindowsCopilot'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Windows Recall ---
        Registry 'Recall_Disable'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Ensure    = 'Present'
            ValueName = 'AllowRecall'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Recall_DisableSnapshots'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Ensure    = 'Present'
            ValueName = 'TurnOffSavingSnapshots'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'AI_DisableDataAnalysis'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
            Ensure    = 'Present'
            ValueName = 'DisableAIDataAnalysis'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Cortana & Search ---
        Registry 'Search_DisableCortana'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure    = 'Present'
            ValueName = 'AllowCortana'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Search_DisableWebSearch'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure    = 'Present'
            ValueName = 'DisableWebSearch'
            ValueType = 'Dword'
            ValueData = '1'
        }

        Registry 'Search_DisableConnectedSearch'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure    = 'Present'
            ValueName = 'ConnectedSearchUseWeb'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Search_DisableBing'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure    = 'Present'
            ValueName = 'BingSearchEnabled'
            ValueType = 'Dword'
            ValueData = '0'
        }

        Registry 'Search_DisableHighlights'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            Ensure    = 'Present'
            ValueName = 'EnableDynamicContentInWSB'
            ValueType = 'Dword'
            ValueData = '0'
        }
    }
}
XOAP_Debloat_W11_24H2_AI_Search -OutputPath 'C:\DSC\XOAP_Debloat_W11_24H2_AI_Search'
