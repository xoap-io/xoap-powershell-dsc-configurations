<#PSScriptInfo
.VERSION 1.0.0
.GUID 23579591-4d15-492d-88fe-1f8365d8a0da
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT Copyright the DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/iSCSIDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/iSCSIDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module iSCSIDsc

<#
    .DESCRIPTION
    This example installs the iSCSI Target Server, creates two
    iSCSI Virtal Disks and then a new iSCSI Target called Cluster
    with the two Virtual Disks assigned. The iSCSI target will accept
    connections from cluster01.contoso.com, cluster02.contoso.com
    or cluster03.contoso.com.
#>
Configuration iSCSIServerTarget_ConfigureServerTarget_Config"
{
    Import-DscResource -Module iSCSIDsc

    Node localhost
    {
        WindowsFeature iSCSITargetServerInstall
        {
            Ensure = "Present"
            Name   = "FS-iSCSITarget-Server"
        }

        iSCSIVirtualDisk iSCSIClusterVDisk01
        {
            Ensure      = 'Present'
            Path        = 'D:\iSCSIVirtualDisks\ClusterVdisk01.vhdx'
            DiskType    = 'Dynamic'
            SizeBytes   = 20GB
            Description = 'Cluster Virtual Disk 01'
            DependsOn   = "[WindowsFeature]ISCSITargetServerInstall"
        } # End of iSCSIVirtualDisk Resource

        iSCSIVirtualDisk iSCSIClusterVDisk02
        {
            Ensure      = 'Present'
            Path        = 'D:\iSCSIVirtualDisks\ClusterVdisk02.vhdx'
            DiskType    = 'Dynamic'
            SizeBytes   = 10GB
            Description = 'Cluster Virtual Disk 02'
            DependsOn   = "[WindowsFeature]ISCSITargetServerInstall"
        } # End of iSCSIVirtualDisk Resource

        iSCSIServerTarget iSCSIClusterTarget
        {
            Ensure       = 'Present'
            TargetName   = 'Cluster'
            InitiatorIds = 'iqn.1991-05.com.microsoft:cluster01.contoso.com','iqn.1991-05.com.microsoft:cluster02.contoso.com','iqn.1991-05.com.microsoft:cluster03.contoso.com'
            Paths        = 'D:\iSCSIVirtualDisks\ClusterVdisk01.vhdx','D:\iSCSIVirtualDisks\ClusterVdisk02.vhdx'
            iSNSServer   = 'isns.contoso.com'
            DependsOn    = "[iSCSIVirtualDisk]iSCSIClusterVDisk01","[iSCSIVirtualDisk]iSCSIClusterVDisk01"
        } # End of iSCSIServerTarget Resource
    } # End of Node
} # End of Configuration
