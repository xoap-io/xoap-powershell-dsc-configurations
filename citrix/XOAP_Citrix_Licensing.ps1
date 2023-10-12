Configuration 'XOAP_Citrix_Licensing'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'XOAP_Citrix_Licensing'
    {
        WindowsFeature 'RDS-Licensing'
        {
            Name    = 'RDS-Licensing'
            Ensure  = 'Present'
        }
        
        WindowsFeature 'RDS-Licensing-UI'
        {
            Name    = 'RDS-Licensing-UI'
            Ensure  = 'Present'
        }
    }
}
