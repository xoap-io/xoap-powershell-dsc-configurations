# DSC Configuration: XOAP_FileServer_DFS
# Purpose: Configures a Windows File Server with DFS Namespace and Replication.
# Note: Update DomainName, NamespaceRoot, and TargetPath before applying.
Configuration 'XOAP_FileServer_DFS'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'DFSDsc'                -ModuleVersion '4.4.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_FileServer_DFS'
    {
        # --- Windows Features ---
        WindowsFeature 'FS_FileServer'
        {
            Name   = 'FS-FileServer'
            Ensure = 'Present'
        }

        WindowsFeature 'FS_DFS_Namespace'
        {
            Name      = 'FS-DFS-Namespace'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]FS_FileServer'
        }

        WindowsFeature 'FS_DFS_Replication'
        {
            Name      = 'FS-DFS-Replication'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]FS_FileServer'
        }

        WindowsFeature 'RSAT_DFS_Mgmt_Con'
        {
            Name   = 'RSAT-DFS-Mgmt-Con'
            Ensure = 'Present'
        }

        WindowsFeature 'FS_Resource_Manager'
        {
            Name   = 'FS-Resource-Manager'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'DFS'
        {
            Name        = 'Dfs'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[WindowsFeature]FS_DFS_Namespace'
        }

        Service 'DFSR'
        {
            Name        = 'DFSR'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[WindowsFeature]FS_DFS_Replication'
        }

        # --- Shared folder ---
        File 'DataShare'
        {
            Type            = 'Directory'
            Ensure          = 'Present'
            DestinationPath = 'D:\Shares\Data'
        }

        # --- DFS Namespace Root ---
        DFSNamespaceRoot 'NamespaceRoot'
        {
            Path          = '\\contoso.local\Files'
            TargetPath    = '\\fileserver01\Files'
            Ensure        = 'Present'
            Type          = 'DomainV2'
            TimeToLiveSec = 300
            DependsOn     = '[WindowsFeature]FS_DFS_Namespace','[Service]DFS'
        }

        # --- DFS Namespace Folder ---
        DFSNamespaceFolder 'DataFolder'
        {
            Path          = '\\contoso.local\Files\Data'
            TargetPath    = '\\fileserver01\Data'
            Ensure        = 'Present'
            TimeToLiveSec = 300
            DependsOn     = '[DFSNamespaceRoot]NamespaceRoot'
        }
    }
}
XOAP_FileServer_DFS -OutputPath 'C:\DSC\XOAP_FileServer_DFS'
