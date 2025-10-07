configuration 'xoap-consultant-config'
{
    Import-DscResource -ModuleName 'RISBaselineDSC'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'XOAPBaselineModuleDSC'

    Node "xoap-consultant-config"
    {
        RisBaselineMeta "Baseline Configuration"
        {
            Include_RISActivateBitLocker = $true
            Include_RISActiveSetup = $true
            Include_RISDeactivateGuestAccess = $true
            Include_RISDriverInstallation = $true
            Include_RISIEExplorer = $true
            Include_RISMSOfficeSettings = $true
            Include_RISNetworking = $true
            Include_RISNTFSPermissions = $true
            Include_RISOptimization = $true
            Include_RISOptionalFeatures = $true
            Include_RISPowerConfiguration = $true
            Include_RISPowerShellModules = $true
            Include_RISChangeLCMDefaults = $true
            Include_RISOneDrive = $true
            Include_RISScheduledTasks = $true
            Include_RISSecurityPolicy = $true
            Include_RISServices = $true
        }

        WindowsOptionalFeature "Internet-Explorer-Optional-amd64"
        {
            Name    = "Internet-Explorer-Optional-amd64"
            Ensure  = "Disable"
        }

        WindowsOptionalFeature "Microsoft-Hyper-V-All"
        {
            Name    = "Microsoft-Hyper-V-All"
            Ensure  = "Enable"
        }

        WindowsOptionalFeature "Containers"
        {
            Name    = "Containers"
            Ensure  = "Enable"
        }

        WindowsOptionalFeature "Microsoft-Windows-Subsystem-Linux"
        {
            Name    = "Microsoft-Windows-Subsystem-Linux"
            Ensure  = "Enable"
        }

        WindowsOptionalFeature "TelnetClient"
        {
            Name    = "TelnetClient"
            Ensure  = "Enable"
        }
    } 
}