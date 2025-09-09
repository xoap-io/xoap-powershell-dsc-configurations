Configuration 'Citrix_Director'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_Director'
    {
        # IIS & Citrix Director required features
        $features = @(
            'Web-Server',
            'Web-WebServer',
            'Web-Common-Http',
            'Web-Default-Doc',
            'Web-Dir-Browsing',
            'Web-Http-Errors',
            'Web-Static-Content',
            'Web-Http-Redirect',
            'Web-Health',
            'Web-Http-Logging',
            'Web-Log-Libraries',
            'Web-Http-Tracing',
            'Web-Performance',
            'Web-Stat-Compression',
            'Web-Dyn-Compression',
            'Web-Security',
            'Web-Filtering',
            'Web-Basic-Auth',
            'Web-Windows-Auth',
            'Web-App-Dev',
            'Web-Net-Ext45',
            'Web-ASP',
            'Web-Asp-Net45',
            'Web-CGI',
            'Web-ISAPI-Ext',
            'Web-ISAPI-Filter',
            'Web-Includes',
            'Web-Mgmt-Tools',
            'Web-Mgmt-Console',
            'Web-Mgmt-Compat',
            'Web-Metabase',
            'Web-Lgcy-Mgmt-Console',
            'Web-Lgcy-Scripting',
            'Web-WMI',
            'Web-Scripting-Tools',
            'NET-Framework-45-ASPNET',
            'NET-WCF-HTTP-Activation45',
            'Remote-Assistance',
            'WAS',
            'WAS-Process-Model',
            'WAS-Config-APIs',
            'RSAT-AD-PowerShell',
            'Web-Mgmt-Service',
            'Web-Server-Management-Tools',
            'Web-Request-Monitor',
            'Web-Server-Admin-Tools'
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

        # Disable SSL 3.0
        Registry 'DisableSSL3' {
            Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
            Ensure    = 'Present'
            ValueName = 'Enabled'
            ValueType = 'DWORD'
            ValueData = 0
        }

        # Enable IIS logging
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

        # Citrix Director - Disable usage analytics and guided help
        Registry 'DisableDirectorAnalytics' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Director'
            Ensure      = 'Present'
            ValueName   = 'DisableGoogleAnalytics'
            ValueType   = 'DWORD'
            ValueData   = 1
        }

        # Citrix Director - Disable guided help
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
    }
}
