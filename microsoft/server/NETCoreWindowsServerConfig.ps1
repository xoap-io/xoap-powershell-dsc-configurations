
<#PSScriptInfo

.VERSION 0.1.0

.GUID e4ecdd34-18d1-4e17-9e34-8d13268fa923

.AUTHOR Michael Greene

.COMPANYNAME Microsoft

.COPYRIGHT 

.TAGS DSCConfiguration

.LICENSEURI https://github.com/Microsoft/ASPNETCoreWindowsConfig/blob/master/LICENSE

.PROJECTURI https://github.com/Microsoft/ASPNETCoreWindowsConfig

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
https://github.com/Microsoft/ASPNETCoreWindowsConfig/blob/master/README.md#releasenotes

.PRIVATEDATA 2016-Datacenter-Server-Core

#>

# Requires -Module @{modulename = 'xWebAdministration'; moduleversion = '1.19.0.0'}
# Requires -module @{ModuleName = 'xPendingReboot'; ModuleVersion = '0.3.0.0'}

<# 

.DESCRIPTION 
 PowerShell Desired State Configuration for deploying and configuring
 ASP.NET Core on Windows Server.

 Based on documentation at:
 https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/?tabs=aspnetcore2x

#> 

configuration NETCoreWindowsServerConfig
{

    Import-DscResource -ModuleName 'xWebAdministration'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node NETCoreWindowsServerConfig
    {
        WindowsFeature WebServer
        {
            Ensure  = 'Present'
            Name    = 'Web-Server'
        }

        # Credit to Erik Onarheim for Argument values used with the Package resource in Gist:
        # https://gist.github.com/eonarheim/703e0f1807b26066d6a2ff5acf4f662d
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
NETCoreWindowsServerConfig