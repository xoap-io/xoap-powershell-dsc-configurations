Configuration Configure_Firewall
{
Import-DSCResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node Configure_Firewall
    {
        Firewall 'EnableBuiltInFirewallRule'
        {
            Name                  = 'IIS-WebServerRole-HTTP-In-TCP'
            Ensure                = 'Present'
            Enabled               = 'True'
        }
    }
}
Configure_Firewall