configuration 'xoap-aws-workspace-w2k16'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'XOAPBaselineModuleDSC'
    Import-DscResource -ModuleName 'LanguageDSC'
    Import-DscResource -ModuleName 'RISBaselineDSC'

    Node "xoap-aws-workspace-w2k16"
    {
        # Windows Optional Features

        WindowsFeature "IISFeature"
        {
            Name = "Web-Server"
            IncludeAllSubFeature = $true
            Ensure = 'Present'
        }

        File "TextFile"
        {
            Ensure = 'Present'
            DestinationPath = "C:\TextFile.txt"
            Contents = "This .txt will be created if the IIS is installed. Check if the IIS is installed."
            Force = $true
            DependsOn = "[WindowsFeature]IISFeature"
        }

        RisBaselineMeta "RISConfigs"
        {
            Include_RISChangeLCMDefaults = $true
        }

        # Language Package is required
        Language "SetLanguage"
        {
            IsSingleInstance = 'Yes'
            LocationID = 94
            MUILanguage = "de-DE"
            MUIFallbackLanguage = "en-US"
            SystemLocale = "de-DE"
            RemoveInputLanguages = @("0409:00000409")
            AddInputLanguages = @("0407:00000407")
            UserLocale = "en-US"
            CopySystem = $true
            CopyNewUser = $true
        }
    }
}