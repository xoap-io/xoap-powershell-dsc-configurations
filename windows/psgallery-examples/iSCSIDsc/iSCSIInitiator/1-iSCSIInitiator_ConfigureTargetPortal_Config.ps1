<#PSScriptInfo
.VERSION 1.0.0
.GUID b5db6465-b609-4e35-b7aa-ddc62efc8553
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
    This example starts the MSiSCSI service on a cluster node and then configures an iSCSI Target
    Portal and then connects to the iSCSI Target.
#>
Configuration iSCSIInitiator_ConfigureTargetPortal_Config"
{
    Import-DscResource -Module iSCSIDSc

    Node localhost
    {
        Service iSCSIService
        {
            Name        = 'MSiSCSI'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        iSCSIInitiator iSCSIInitiator
        {
            Ensure                 = 'Present'
            NodeAddress            = 'iqn.1991-05.com.microsoft:fileserver01-cluster-target'
            TargetPortalAddress    = '192.168.128.10'
            InitiatorPortalAddress = '192.168.128.20'
            IsPersistent           = $true
            iSNSServer             = 'isns.contoso.com'
            DependsOn              = "[Service]iSCSIService"
        } # End of iSCSIInitiator Resource
    } # End of Node
} # End of Configuration
