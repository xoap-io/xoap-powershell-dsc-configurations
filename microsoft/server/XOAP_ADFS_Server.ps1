# DSC Configuration: XOAP_ADFS_Server
# Purpose: Installs ADFS role with required IIS prerequisites.
# Note: AdfsDsc module required. Farm configuration requires a certificate thumbprint
#       and service account. Customize variables at the bottom before applying.
Configuration 'XOAP_ADFS_Server'
{
    param (
        [Parameter(Mandatory)]
        [PSCredential]$ServiceAccountCredential,
        [Parameter(Mandatory)]
        [string]$CertificateThumbprint,
        [string]$FederationServiceName = 'adfs.contoso.com'
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AdfsDsc'               -ModuleVersion '1.1.0'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'XOAP_ADFS_Server'
    {
        # --- Windows Features ---
        WindowsFeature 'ADFS_Federation'
        {
            Name                 = 'ADFS-Federation'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeature 'Web_Server'
        {
            Name                 = 'Web-Server'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
            DependsOn            = '[WindowsFeature]ADFS_Federation'
        }

        WindowsFeature 'Web_Mgmt_Console'
        {
            Name      = 'Web-Mgmt-Console'
            Ensure    = 'Present'
            DependsOn = '[WindowsFeature]Web_Server'
        }

        WindowsFeature 'RSAT_ADFS'
        {
            Name      = 'RSAT-AD-AdminCenter'
            Ensure    = 'Present'
        }

        # --- ADFS Farm ---
        AdfsFarm 'ADFS_Farm'
        {
            FederationServiceName        = $FederationServiceName
            FederationServiceDisplayName = 'Contoso ADFS'
            CertificateThumbprint        = $CertificateThumbprint
            ServiceAccountCredential     = $ServiceAccountCredential
            Ensure                       = 'Present'
            DependsOn                    = '[WindowsFeature]ADFS_Federation'
        }

        # --- Services ---
        Service 'ADFSSRV'
        {
            Name        = 'adfssrv'
            State       = 'Running'
            StartupType = 'Automatic'
            DependsOn   = '[AdfsFarm]ADFS_Farm'
        }

        # --- Security: Disable legacy auth endpoints ---
        Registry 'ADFS_DisableWsTrustWindowsAuth'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ADFS'
            Ensure    = 'Present'
            ValueName = 'EnableWindowsTransportApplication'
            ValueType = 'Dword'
            ValueData = '0'
        }
    }
}
