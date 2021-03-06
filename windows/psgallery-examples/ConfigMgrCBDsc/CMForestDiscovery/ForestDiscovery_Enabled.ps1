<#
    .SYNOPSIS
        A DSC configuration script to enable AD Forest Discovery for Configuration Manager.
#>
Configuration Example"
{
    Import-DscResource -ModuleName ConfigMgrCBDsc

    Node localhost
    {
        CMForestDiscovery ExampleSettings
        {
            SiteCode                                  = 'Lab'
            Enabled                                   = $true
            ScheduleInterval                          = 'Days'
            ScheduleCount                             = 7
            EnableActiveDirectorySiteBoundaryCreation = $false
            EnableSubnetBoundaryCreation              = $true
        }
    }
}
