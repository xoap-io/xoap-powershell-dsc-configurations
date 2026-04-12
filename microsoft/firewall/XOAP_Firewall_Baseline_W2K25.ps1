# DSC Configuration: XOAP_Firewall_Baseline_W2K25
# Purpose: Configures Windows Firewall profiles and key rules for Windows Server 2025.

Configuration 'XOAP_Firewall_Baseline_W2K25'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '9.0.0'

    Node 'XOAP_Firewall_Baseline_W2K25'
    {
        # --- Firewall Profiles ---
        FirewallProfile 'Profile_Domain'
        {
            Name                            = 'Domain'
            Enabled                         = 'True'
            DefaultInboundAction            = 'Block'
            DefaultOutboundAction           = 'Allow'
            NotifyOnListen                  = 'False'
            AllowUnicastResponseToMulticast = 'True'
            LogFileName                     = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes             = 16384
            LogAllowed                      = 'False'
            LogBlocked                      = 'True'
            LogIgnored                      = 'False'
        }

        FirewallProfile 'Profile_Private'
        {
            Name                            = 'Private'
            Enabled                         = 'True'
            DefaultInboundAction            = 'Block'
            DefaultOutboundAction           = 'Allow'
            NotifyOnListen                  = 'True'
            AllowUnicastResponseToMulticast = 'True'
            LogFileName                     = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes             = 16384
            LogAllowed                      = 'False'
            LogBlocked                      = 'True'
            LogIgnored                      = 'False'
        }

        FirewallProfile 'Profile_Public'
        {
            Name                            = 'Public'
            Enabled                         = 'True'
            DefaultInboundAction            = 'Block'
            DefaultOutboundAction           = 'Allow'
            NotifyOnListen                  = 'True'
            AllowUnicastResponseToMulticast = 'True'
            LogFileName                     = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes             = 16384
            LogAllowed                      = 'False'
            LogBlocked                      = 'True'
            LogIgnored                      = 'False'
        }

        # --- Inbound Allow Rules ---
        Firewall 'Allow_RDP_Domain'
        {
            Name        = 'XOAP-RDP-In'
            DisplayName = 'Remote Desktop (TCP-In) - Domain'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain')
            Direction   = 'Inbound'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = @('3389')
            Description = 'Allow RDP inbound on Domain profile only'
        }

        Firewall 'Allow_WinRM_HTTP_Domain'
        {
            Name        = 'XOAP-WinRM-HTTP-In'
            DisplayName = 'Windows Remote Management (HTTP-In) - Domain'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain')
            Direction   = 'Inbound'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = @('5985')
            Description = 'Allow WinRM HTTP inbound on Domain profile only'
        }

        Firewall 'Allow_WinRM_HTTPS_Domain'
        {
            Name        = 'XOAP-WinRM-HTTPS-In'
            DisplayName = 'Windows Remote Management (HTTPS-In) - Domain'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain')
            Direction   = 'Inbound'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = @('5986')
            Description = 'Allow WinRM HTTPS inbound on Domain profile only'
        }

        Firewall 'Allow_SMB_Domain'
        {
            Name        = 'XOAP-SMB-In'
            DisplayName = 'File and Printer Sharing (SMB-In) - Domain'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain')
            Direction   = 'Inbound'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = @('445')
            Description = 'Allow SMB inbound on Domain profile only'
        }

        Firewall 'Allow_RPC_Domain'
        {
            Name        = 'XOAP-RPC-In'
            DisplayName = 'RPC Endpoint Mapper (TCP-In) - Domain'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain')
            Direction   = 'Inbound'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = @('135')
            Description = 'Allow RPC Endpoint Mapper inbound on Domain profile'
        }

        # --- Inbound Block Rules ---
        Firewall 'Block_SMB_Public'
        {
            Name        = 'XOAP-Block-SMB-Public-In'
            DisplayName = 'Block SMB (TCP 445) - Public'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Public')
            Direction   = 'Inbound'
            Action      = 'Block'
            Protocol    = 'TCP'
            LocalPort   = @('445')
            Description = 'Block SMB inbound on Public profile'
        }

        Firewall 'Block_RDP_Public'
        {
            Name        = 'XOAP-Block-RDP-Public-In'
            DisplayName = 'Block RDP (TCP 3389) - Public'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Public')
            Direction   = 'Inbound'
            Action      = 'Block'
            Protocol    = 'TCP'
            LocalPort   = @('3389')
            Description = 'Block RDP inbound on Public profile'
        }

        Firewall 'Block_Telnet_All'
        {
            Name        = 'XOAP-Block-Telnet-In'
            DisplayName = 'Block Telnet (TCP 23) - All'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain', 'Private', 'Public')
            Direction   = 'Inbound'
            Action      = 'Block'
            Protocol    = 'TCP'
            LocalPort   = @('23')
            Description = 'Block Telnet inbound on all profiles'
        }
    }
}

XOAP_Firewall_Baseline_W2K25 -OutputPath 'C:\DSC\XOAP_Firewall_Baseline_W2K25'
