configuration 'Configure_IIS_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'WebAdministrationDSC' -ModuleVersion '4.1.0'

    Node 'Configure_IIS_Server'
    {
        WindowsFeature 'WebServer'
        {
            Ensure  = 'Present'
            Name    = 'Web-Server'
        }

        WebSiteDefaults 'SiteDefaults'
        {
            IsSingleInstance        = 'Yes'
            LogFormat               = 'IIS'
            LogDirectory            = 'C:\inetpub\logs\LogFiles'
            TraceLogDirectory       = 'C:\inetpub\logs\FailedReqLogFiles'
            DefaultApplicationPool  = 'DefaultAppPool'
            AllowSubDirConfig       = 'true'
            DependsOn               = '[WindowsFeature]WebServer'
        }

        WebAppPoolDefaults 'PoolDefaults'
        {
        IsSingleInstance      = 'Yes'
        ManagedRuntimeVersion = 'v4.0'
        IdentityType          = 'ApplicationPoolIdentity'
        DependsOn             = '[WindowsFeature]WebServer'
        }

        <#
        If you would like DSC to deploy your content in to a new site,
        this section provides an example, as well as use of a certificate.

        See more examples in the xWebAdministration resource project.
        https://github.com/PowerShell/xWebAdministration/tree/dev/Examples

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
        #>
    }
}
