<#PSScriptInfo
.VERSION 1.0.0
.GUID 9eee170a-2a36-49d9-bcb3-7523b5f80856
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/ActiveDirectoryCSDsc/blob/main/LICENSE
.PROJECTURI https://github.com/dsccommunity/ActiveDirectoryCSDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module ActiveDirectoryCSDsc

<#
    .DESCRIPTION
        This example will add the Active Directory Certificate Services Enrollment
        Policy Web Service feature to a server and install a new instance to
        accepting Certificate authentication. The Enrollment Policy Web Service
        will operate in key-based renewal mode. The local machine certificate with the
        thumbprint 'f0262dcf287f3e250d1760508c4ca87946006e1e' will be used for the
        IIS web site for SSL encryption.
#>
Configuration AdcsEnrollmentPolicyWebService_InstallCertificateAuthentication_Config"
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -Module ActiveDirectoryCSDsc

    Node localhost
    {
        WindowsFeature ADCS-Enroll-Web-Pol
        {
            Ensure = 'Present'
            Name   = 'ADCS-Enroll-Web-Pol'
        }

        AdcsEnrollmentPolicyWebService EnrollmentPolicyWebService
        {
            AuthenticationType = 'Certificate'
            SslCertThumbprint  = 'f0262dcf287f3e250d1760508c4ca87946006e1e'
            Credential         = $Credential
            KeyBasedRenewal    = $true
            Ensure             = 'Present'
            DependsOn          = '[WindowsFeature]ADCS-Enroll-Web-Pol'
        }
    }
}
