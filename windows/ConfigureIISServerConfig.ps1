configuration iis-server-config
{
    Import-DscResource -ModuleName 'xWebAdministration'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node iis-server-config
    {
        WindowsFeature WebServer
        {
            Ensure  = 'Present'
            Name    = 'Web-Server'
        }

        xWebSiteDefaults SiteDefaults
        {
            IsSingleInstance        = 'Yes'
            LogFormat               = 'IIS'
            LogDirectory            = 'C:\inetpub\logs\LogFiles'
            TraceLogDirectory       = 'C:\inetpub\logs\FailedReqLogFiles'
            DefaultApplicationPool  = 'DefaultAppPool'
            AllowSubDirConfig       = 'true'
            DependsOn               = '[WindowsFeature]WebServer'
        }

        xWebAppPoolDefaults PoolDefaults
        {
        IsSingleInstance      = 'Yes'
        ManagedRuntimeVersion = 'v4.0'
        IdentityType          = 'ApplicationPoolIdentity'
        DependsOn             = '[WindowsFeature]WebServer'
        }

        File WebContent
        {
            Ensure          = "Present"
            SourcePath      = $SourcePath
            DestinationPath = $DestinationPath
            Recurse         = $true
            Type            = "Directory"
            DependsOn       = "[WindowsFeature]AspNet45"
        }

        xWebsite NewWebsite
        {
            Ensure          = "Present"
            Name            = $WebSiteName
            State           = "Started"
            PhysicalPath    = $DestinationPath
            DependsOn       = "[File]WebContent"
            BindingInfo     = MSFT_xWebBindingInformation
            {
                Protocol              = 'https'
                Port                  = '443'
                CertificateStoreName  = 'MY'
                CertificateThumbprint = 'BB84DE3EC423DDDE90C08AB3C5A828692089493C'
                HostName              = $Website
                IPAddress             = '*'
                SSLFlags              = '1'
            }
        }

    }
}
iis-server-config
