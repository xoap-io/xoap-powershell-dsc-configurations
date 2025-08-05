Configuration 'Citrix_Director'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'Citrix_Director'
    {
        # IIS & Citrix Director required features
        $features = @(
            'Web-Server','Web-WebServer','Web-Common-Http','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-Static-Content',
            'Web-Http-Redirect','Web-Health','Web-Http-Logging','Web-Log-Libraries','Web-Http-Tracing','Web-Performance','Web-Stat-Compression',
            'Web-Dyn-Compression','Web-Security','Web-Filtering','Web-Basic-Auth','Web-Windows-Auth','Web-App-Dev','Web-Net-Ext45','Web-ASP',
            'Web-Asp-Net45','Web-CGI','Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Includes','Web-Mgmt-Tools','Web-Mgmt-Console','Web-Mgmt-Compat',
            'Web-Metabase','Web-Lgcy-Mgmt-Console','Web-Lgcy-Scripting','Web-WMI','Web-Scripting-Tools','NET-Framework-45-ASPNET',
            'NET-WCF-HTTP-Activation45','Remote-Assistance','WAS','WAS-Process-Model','WAS-Config-APIs',
            'RSAT-AD-PowerShell','Web-Mgmt-Service','Web-Server-Management-Tools','Web-Request-Monitor','Web-Server-Admin-Tools'
        )
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Registry hardening (example: disable SSL 2.0/3.0, enable logging)
        Registry 'DisableSSL2' {
            Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'DWORD'
            ValueData = 0
        }
        Registry 'DisableSSL3' {
            Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'DWORD'
            ValueData = 0
        }
        Registry 'EnableIISLogging' {
            Key       = 'HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters'
            Ensure    = 'Present'
            ValueName = 'LogInUTF8'
            ValueType = 'DWORD'
            ValueData = 1
        }

        # Firewall rules (example: open port 80/443)
        Script 'OpenHTTPPort' {
            GetScript  = { return @{ Result = (Get-NetFirewallRule -DisplayName 'IIS HTTP') } }
            SetScript  = { New-NetFirewallRule -DisplayName 'IIS HTTP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 }
            TestScript = { (Get-NetFirewallRule -DisplayName 'IIS HTTP') -ne $null }
        }
        Script 'OpenHTTPSPort' {
            GetScript  = { return @{ Result = (Get-NetFirewallRule -DisplayName 'IIS HTTPS') } }
            SetScript  = { New-NetFirewallRule -DisplayName 'IIS HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 }
            TestScript = { (Get-NetFirewallRule -DisplayName 'IIS HTTPS') -ne $null }
        }

        # Ensure IIS service is running and set to automatic
        Service 'W3SVC' {
            Name        = 'W3SVC'
            State       = 'Running'
            StartupType = 'Automatic'
        }
        # Example: Citrix Director service (replace with actual service name if different)
        Service 'CitrixDirector' {
            Name        = 'CitrixDirector'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Windows Server 2022 specific optimizations
        # Disable SMBv1
        Registry 'SMBv1' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'SMB1'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Disable Defender if using 3rd party AV
        Registry 'DisableDefender' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
            Ensure      = 'Present'
            ValueName   = 'DisableAntiSpyware'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Telemetry
        Registry 'Telemetry' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure      = 'Present'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Power Plan - High Performance
        Registry 'PowerPlan' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' # High Performance GUID
        }
        # Event Log - Limit log size
        Registry 'ApplicationLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }
        Registry 'SystemLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }
        # Network - TCP/IP tuning
        Registry 'TcpAutoTuning' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableTCPA'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Storage - Disable Storage Spaces Direct (if not used)
        Registry 'DisableS2D' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\S2D'
            Ensure      = 'Present'
            ValueName   = 'Start'
            ValueType   = 'DWORD'
            ValueData   = 4
        }
        # Citrix Director - Disable usage analytics and guided help
        Registry 'DisableDirectorAnalytics' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Director'
            Ensure      = 'Present'
            ValueName   = 'DisableGoogleAnalytics'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        Registry 'DisableDirectorGuidedHelp' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Director'
            Ensure      = 'Present'
            ValueName   = 'DisableGuidedHelp'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Citrix Director - IIS authentication (Integrated Windows Authentication)
        Script 'ConfigureIISAuthForDirector' {
            GetScript  = { return @{ Result = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name enabled -PSPath 'IIS:\Sites\Default Web Site\Director') } }
            SetScript  = {
                Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name enabled -Value $true -PSPath 'IIS:\Sites\Default Web Site\Director'
                Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -Name enabled -Value $false -PSPath 'IIS:\Sites\Default Web Site\Director'
            }
            TestScript = { ((Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name enabled -PSPath 'IIS:\Sites\Default Web Site\Director').Value -eq $true) -and ((Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -Name enabled -PSPath 'IIS:\Sites\Default Web Site\Director').Value -eq $false) }
        }
        # Security - Harden LSA
        Registry 'RunAsPPL' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure      = 'Present'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Security - Credential Guard
        Registry 'EnableVirtualizationBasedSecurity' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        Registry 'RequirePlatformSecurityFeatures' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'RequirePlatformSecurityFeatures'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
Citrix_Director