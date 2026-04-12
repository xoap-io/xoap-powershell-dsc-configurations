# DSC Configuration: XOAP_FailoverCluster
# Purpose: Configures Windows Server Failover Clustering prerequisites and baseline settings.
Configuration 'XOAP_FailoverCluster'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_FailoverCluster'
    {
        # --- Windows Features ---
        WindowsFeature 'FailoverClustering'
        {
            Name   = 'Failover-Clustering'
            Ensure = 'Present'
        }

        WindowsFeature 'RSAT_Clustering'
        {
            Name   = 'RSAT-Clustering'
            Ensure = 'Present'
        }

        WindowsFeature 'RSAT_Clustering_PowerShell'
        {
            Name   = 'RSAT-Clustering-PowerShell'
            Ensure = 'Present'
        }

        WindowsFeature 'RSAT_Clustering_Mgmt'
        {
            Name   = 'RSAT-Clustering-Mgmt'
            Ensure = 'Present'
        }

        # --- Services ---
        Service 'ClusSvc'
        {
            Name        = 'ClusSvc'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        Service 'ClusNet'
        {
            Name        = 'ClusNet'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # --- Registry: Cluster Heartbeat Settings ---
        Registry 'Cluster_SameSubnetDelay'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClusSvc\Parameters'
            Ensure    = 'Present'
            ValueName = 'SameSubnetDelay'
            ValueType = 'Dword'
            ValueData = '1000'
        }

        Registry 'Cluster_SameSubnetThreshold'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClusSvc\Parameters'
            Ensure    = 'Present'
            ValueName = 'SameSubnetThreshold'
            ValueType = 'Dword'
            ValueData = '10'
        }

        Registry 'Cluster_CrossSubnetDelay'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClusSvc\Parameters'
            Ensure    = 'Present'
            ValueName = 'CrossSubnetDelay'
            ValueType = 'Dword'
            ValueData = '1000'
        }
    }
}
XOAP_FailoverCluster -OutputPath 'C:\DSC\XOAP_FailoverCluster'
