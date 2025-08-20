
# DSC Configuration: Configure_IIS_Server
# Purpose: Installs IIS, sets default logging/app pool settings, and provides example for deploying content and a new site.
configuration 'Configure_IIS_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'WebAdministrationDSC' -ModuleVersion '4.1.0'

    Node 'Configure_IIS_Server'
    {
        # Installs the IIS Web-Server feature
        WindowsFeature 'IIS_WebServer'
        {
            Ensure  = 'Present'
            Name    = 'Web-Server'
        }

        # Sets default logging and application pool settings for all IIS sites
        WebSiteDefaults 'IIS_SiteDefaults'
        {
            IsSingleInstance        = 'Yes'
            LogFormat               = 'IIS'
            LogDirectory            = 'C:\inetpub\logs\LogFiles'
            TraceLogDirectory       = 'C:\inetpub\logs\FailedReqLogFiles'
            DefaultApplicationPool  = 'DefaultAppPool'
            AllowSubDirConfig       = 'true'
            DependsOn               = '[WindowsFeature]IIS_WebServer'
        }

        # Sets default settings for all IIS application pools
        WebAppPoolDefaults 'IIS_AppPoolDefaults'
        {
            IsSingleInstance      = 'Yes'
            ManagedRuntimeVersion = 'v4.0'
            IdentityType          = 'ApplicationPoolIdentity'
            DependsOn             = '[WindowsFeature]IIS_WebServer'
        }

        <#
        Example: Deploy content and create a new IIS site with HTTPS binding and certificate
        See more examples in the xWebAdministration resource project:
        https://github.com/PowerShell/xWebAdministration/tree/dev/Examples

        File 'WebContent'
        {
            Ensure          = "Present"
            SourcePath      = $SourcePath
            DestinationPath = $DestinationPath
            Recurse         = $true
            Type            = "Directory"
            DependsOn       = "[WindowsFeature]AspNet45"
        }

        xWebsite 'NewWebsite'
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
        #>
    }
}
