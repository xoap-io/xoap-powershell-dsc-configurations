Configuration firewall-config
{
    Import-DSCResource -ModuleName NetworkingDsc

    Node firewall-config
    {
        Firewall EnableBuiltInFirewallRule
        {
            Name                  = 'IIS-WebServerRole-HTTP-In-TCP'
            Ensure                = 'Present'
            Enabled               = 'True'
        }
    }
}
firewall-config
