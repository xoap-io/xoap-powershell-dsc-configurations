# DSC Configuration: XOAP_DHCP_Server
# Purpose: Installs and configures a DHCP server with a sample scope.
# Note: Update ScopeId, Name, SubnetMask, LeaseDuration, IPStartRange, IPEndRange,
#       Router, and DNSServer to match your network before applying.
Configuration 'XOAP_DHCP_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xDhcpServer'           -ModuleVersion '3.1.1'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_DHCP_Server'
    {
        # --- Windows Features ---
        WindowsFeature 'DHCP'
        {
            Name                 = 'DHCP'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'RSAT_DHCP'
        {
            Name      = 'RSAT-DHCP'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]DHCP'
        }

        # --- Service ---
        Service 'DHCPServer'
        {
            Name        = 'DHCPServer'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[WindowsFeature]DHCP'
        }

        # --- DHCP Scope ---
        xDhcpServerScope 'MainScope'
        {
            Ensure           = 'Present'
            ScopeId          = '192.168.1.0'
            Name             = 'Main Network Scope'
            SubnetMask       = '255.255.255.0'
            LeaseDuration    = '8.00:00:00'
            IPStartRange     = '192.168.1.100'
            IPEndRange       = '192.168.1.200'
            State            = 'Active'
            DependsOn        = '[Service]DHCPServer'
        }

        # --- DHCP Scope Options (Router + DNS) ---
        xDhcpServerOption 'ScopeOptions'
        {
            Ensure             = 'Present'
            ScopeID            = '192.168.1.0'
            Router             = @('192.168.1.1')
            DnsServerIPAddress = @('192.168.1.10', '192.168.1.11')
            DnsDomain          = 'contoso.local'
            DependsOn          = '[xDhcpServerScope]MainScope'
        }

        # --- DHCP Authorization (AD-joined servers) ---
        Registry 'DHCP_DisableNameCheck'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters'
            Ensure    = 'Present'
            ValueName = 'DisableRogueDetection'
            ValueType = 'Dword'
            ValueData = '0'
        }
    }
}
XOAP_DHCP_Server -OutputPath 'C:\DSC\XOAP_DHCP_Server'
