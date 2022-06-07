configuration net-core-windows-server-config
{
    Import-DscResource -ModuleName 'xWebAdministration'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node net-core-windows-server-config
    {
        WindowsFeature WebServer
        {
            Ensure  = 'Present'
            Name    = 'Web-Server'
        }

        Package InstallDotNetCoreHostingBundle {
            Name      = 'Microsoft ASP.NET Core Module'
            ProductId = '49FDA0AA-4653-4432-88BF-ADAA61DD5735'
            Arguments = "/quiet /norestart /log $env:TEMP\dnhosting_install.log"
            Path      = 'https://download.microsoft.com/download/1/1/0/11046135-4207-40D3-A795-13ECEA741B32/DotNetCore.2.0.5-WindowsHosting.exe'
            DependsOn = '[WindowsFeature]WebServer'
        }

        Environment DotNet
        {
            Name      = 'Path'
            Ensure    = 'Present'
            Value     = 'C:\Program Files\dotnet\;'
            Path      = $true
            DependsOn = '[Package]InstallDotNetCoreHostingBundle'
        }

        PendingReboot AfterDotNetCoreHosting
        {
            Name             = 'AfterDotNetCoreHosting'
            SkipCcmClientSDK = $true
            DependsOn        = '[Package]InstallDotNetCoreHostingBundle'
        }

        xWebsite DefaultSite
        {
            Ensure          = 'Present'
            Name            = 'Default Web Site'
            State           = 'Stopped'
            PhysicalPath    = 'C:\inetpub\wwwroot'
            DependsOn       = '[WindowsFeature]WebServer'
        }

        File Content
        {
            Ensure          = 'Present'
            DestinationPath = 'c:\inetpub\content'
            Type            = 'Directory'
        }

        File Logs
        {
            Ensure          = 'Present'
            DestinationPath = 'c:\inetpub\content\logs'
            Type            = 'Directory'
            DependsOn       = '[File]Content'
        }

        xWebAppPool AppPool
        {
            Ensure                  = 'Present'
            Name                    = 'AppPool'
            State = 'Started'
        }

        xWebsite Website
        {
            Ensure          = 'Present'
            Name            = 'Website'
            State           = 'Started'
            PhysicalPath    = 'c:\inetpub\content'
            BindingInfo = MSFT_xWebBindingInformation
                {
                    Protocol              = 'Http'
                    Port                  = '80'
                    IPAddress             = '*'
                    Hostname              = '*'
                }
            DependsOn       = '[File]Content','[xWebAppPool]AppPool'
        }

        xWebApplication SampleApplication
        {
            Ensure                  = 'Present'
            Name                    = 'Application'
            WebAppPool              = 'AppPool'
            Website                 = 'Website'
            PreloadEnabled          = $true
            ServiceAutoStartEnabled = $true
            AuthenticationInfo      = MSFT_xWebApplicationAuthenticationInformation
            {
                Anonymous   = $true
                Basic       = $false
                Digest      = $false
                Windows     = $false
            }
            SslFlags                = ''
            PhysicalPath            = 'c:\inetpub\content'
            DependsOn               = '[xWebsite]WebSite','[xWebAppPool]AppPool'
        }
    }
}
net-core-windows-server-config
