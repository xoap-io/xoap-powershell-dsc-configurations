# DSC Configuration: XOAP_ADCS_Server
# Purpose: Installs and configures Active Directory Certificate Services (Enterprise Root CA).
# Note: Requires an AD domain. Update CACommonName before applying.
Configuration 'XOAP_ADCS_Server'
{
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'CertificateDsc'        -ModuleVersion '5.1.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_ADCS_Server'
    {
        # --- Windows Features ---
        WindowsFeature 'ADCS_Cert_Authority'
        {
            Name                 = 'ADCS-Cert-Authority'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'ADCS_Web_Enrollment'
        {
            Name      = 'ADCS-Web-Enrollment'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]ADCS_Cert_Authority'
        }

        WindowsFeature 'RSAT_ADCS'
        {
            Name      = 'RSAT-ADCS'
            Ensure    = 'Present'
        }

        WindowsFeature 'Web_Server'
        {
            Name                 = 'Web-Server'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        # --- Certificate Authority ---
        AdcsCertificationAuthority 'EnterpriseRootCA'
        {
            IsSingleInstance   = 'Yes'
            Ensure             = 'Present'
            CAType             = 'EnterpriseRootCA'
            CACommonName       = 'Contoso-Root-CA'
            CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName  = 'SHA256'
            KeyLength          = 4096
            Credential         = $Credential
            DependsOn          = '[WindowsFeature]ADCS_Cert_Authority'
        }

        # --- Web Enrollment ---
        AdcsWebEnrollment 'WebEnrollment'
        {
            IsSingleInstance = 'Yes'
            Ensure           = 'Present'
            Credential       = $Credential
            DependsOn        = '[AdcsCertificationAuthority]EnterpriseRootCA','[WindowsFeature]ADCS_Web_Enrollment'
        }

        # --- Service ---
        Service 'CertSvc'
        {
            Name        = 'CertSvc'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[AdcsCertificationAuthority]EnterpriseRootCA'
        }
    }
}
