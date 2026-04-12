# DSC Configuration: XOAP_Firewall_Baseline_W11_24H2
# Purpose: Configures Windows Firewall profiles and key rules for Windows 11 24H2 clients.

Configuration 'XOAP_Firewall_Baseline_W11_24H2'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'NetworkingDsc' -ModuleVersion '9.0.0'

    Node 'XOAP_Firewall_Baseline_W11_24H2'
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
        Firewall 'Allow_RDP_DomainPrivate'
        {
            Name        = 'XOAP-RDP-In'
            DisplayName = 'Remote Desktop (TCP-In) - Domain/Private'
            Ensure      = 'Present'
            Enabled     = 'True'
            Profile     = @('Domain', 'Private')
            Direction   = 'Inbound'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = @('3389')
            Description = 'Allow RDP inbound on Domain and Private profiles'
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
    }
}

XOAP_Firewall_Baseline_W11_24H2 -OutputPath 'C:\DSC\XOAP_Firewall_Baseline_W11_24H2'
