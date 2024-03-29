<#
.EXAMPLE
    This example applies the distributed cache service to both 'server1' and
    'server2'. The ServerProvisionOrder will ensure that it applies it to
    server1 first and then server2, making sure they don't both attempt to
    create the cache at the same time, resuling in errors. A third server
    'server3', which is not included within ServerProvisionOrder, is
    configured as Absent.

    Note: Do not allow plain text passwords in production environments.
#>

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName = 'Server1'
                PSDscAllowPlainTextPassword = $true
            },
            @{
                NodeName = 'Server2'
                PSDscAllowPlainTextPassword = $true
            },
            @{
                NodeName = 'Server3'
                PSDscAllowPlainTextPassword = $true
            }
        )
    }

    Configuration Example
    {
        param(
            [Parameter(Mandatory = $true)]
            [PSCredential]
            $SetupAccount
        )
        Import-DscResource -ModuleName SharePointDsc

        node 'Server1'
        {
            SPDistributedCacheService EnableDistributedCache
            {
                Name                 = 'AppFabricCachingService'
                CacheSizeInMB        = 8192
                ServiceAccount       = 'DEMO\ServiceAccount'
                ServerProvisionOrder = @('Server1','Server2')
                CreateFirewallRules  = $true
                PsDscRunAsCredential = $SetupAccount
            }
        }

        node 'Server2'
        {
            SPDistributedCacheService EnableDistributedCache
            {
                Name                 = 'AppFabricCachingService'
                CacheSizeInMB        = 8192
                ServiceAccount       = 'DEMO\ServiceAccount'
                ServerProvisionOrder = @('Server1','Server2')
                CreateFirewallRules  = $true
                PsDscRunAsCredential = $SetupAccount
            }
        }

        node 'Server3'
        {
            SPDistributedCacheService EnableDistributedCache
            {
                Name                 = 'AppFabricCachingService'
                CacheSizeInMB        = 8192
                ServiceAccount       = 'DEMO\ServiceAccount'
                ServerProvisionOrder = @('Server1','Server2')
                CreateFirewallRules  = $true
                Ensure               = 'Absent'
                PsDscRunAsCredential = $SetupAccount
            }
        }
    }
