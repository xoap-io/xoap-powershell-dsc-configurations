Configuration 'xoap-w10-1909-azure-master-image'
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName xPrinterManagement
    Import-DscResource -ModuleName OneDriveDsc
    Import-DscResource -ModuleName PendingReboot
    Import-DscResource -ModuleName XOAPBaselineModuleDSC
    Import-DscResource -ModuleName XOAPLCMDefaultsDSC
    Import-DSCResource -ModuleName XOAPAzureMasterImageDSC

    Node "xoap-w10-1909-azure-master-image"
    {

        # 00 Configuration_Defaults
        cNtfsPermissionEntry PermissionSet1
        {
            Ensure = 'Present'
            Path = "C:\Windows\Temp"
            Principal = "S-1-1-0"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'ReadAndExecute'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
        }

        # XOAPAzureMasterImageDSC module activation syntax
        XOAPAzureMasterImageDSCMeta "Azure Master Image"
        {
            AzureMasterImage = $true
        }

        # 99_Change_LCM_Defaults
        #final set:Disable automatic reboot
        XOAPLCMDefaultsMeta "Disable RebootIfNeeded"
        {
            Disable_Reboot = $true
        }
    }
}