configuration dns-server-config
{
    Import-DscResource -ModuleName 'xDnsServer'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node dns-server-config
    {
        $ZoneData =
            @{
                PrimaryZone     = 'Contoso.com';
                ARecords        =
                @{
                    'ARecord1'  = '10.0.0.25';
                    'ARecord2'  = '10.0.0.26';
                    'ARecord3'  = '10.0.0.27'
                };
                CNameRecords    =
                @{
                    'www'       = 'ARecord1';
                    'wwwtest'   = 'ARecord2';
                    'wwwqa'     = 'ARecord3'
                }
            },
            @{
                PrimaryZone     = 'Fabrikam.com';
                ARecords        =
                @{
                    'ARecord1'  = '10.0.0.35';
                    'ARecord2'  = '10.0.0.36';
                    'ARecord3'  = '10.0.0.37'
                };
                CNameRecords    =
                @{
                    'www'       = 'ARecord1';
                    'wwwtest'   = 'ARecord2';
                    'wwwqa'     = 'ARecord3'
                }
            }

        WindowsFeature DNS
        {
            Ensure  = 'Present'
            Name    = 'DNS'
            IncludeAllSubFeature = $true
        }

        foreach ($Zone in $ZoneData)
        {
            xDnsServerPrimaryZone $Zone.PrimaryZone
            {
                Ensure    = 'Present'
                Name      = $Zone.PrimaryZone
                DependsOn = '[WindowsFeature]DNS'
            }

            foreach ($ARecord in $Zone.ARecords.Keys)
            {
                xDnsRecord "$($Zone.PrimaryZone)_$ARecord"
                {
                    Ensure    = 'Present'
                    Name      = $ARecord
                    Zone      = $Zone.PrimaryZone
                    Type      = 'ARecord'
                    Target    = $Zone.ARecords[$ARecord]
                    DependsOn = "[WindowsFeature]DNS","[xDnsServerPrimaryZone]$($Zone.PrimaryZone)"
                }
            }

            foreach ($CNameRecord in $Zone.CNameRecords.Keys)
            {
                xDnsRecord "$($Zone.PrimaryZone)_$CNameRecord"
                {
                    Ensure    = 'Present'
                    Name      = $CNameRecord
                    Zone      = $Zone.PrimaryZone
                    Type      = 'CName'
                    Target    = $Zone.CNameRecords[$CNameRecord]
                    DependsOn = "[WindowsFeature]DNS","[xDnsServerPrimaryZone]$($Zone.PrimaryZone)"
                }
            }
        }
    }
}
dns-server-config
