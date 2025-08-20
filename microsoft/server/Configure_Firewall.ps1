
# DSC Configuration: Configure_Firewall
# Purpose: Ensures the built-in IIS HTTP firewall rule is enabled for inbound TCP traffic.
Configuration 'Configure_Firewall'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '8.2.0'

    Node 'Configure_Firewall'
    {
        # Enables the built-in IIS HTTP firewall rule for inbound TCP traffic
        Firewall 'IIS_WebServerRole_HTTP_In_TCP'
        {
            Name    = 'IIS-WebServerRole-HTTP-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
        }
    }
}
