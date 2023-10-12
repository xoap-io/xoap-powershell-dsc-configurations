Configuration 'Configure_Firewall'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DSCResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'

    Node 'Configure_Firewall'
    {
        Firewall 'EnableBuiltInFirewallRule'
        {
            Name                  = 'IIS-WebServerRole-HTTP-In-TCP'
            Ensure                = 'Present'
            Enabled               = 'True'
        }
    }
}
