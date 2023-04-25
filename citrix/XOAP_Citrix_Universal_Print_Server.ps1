
Configuration XOAP_Citrix_Universal_Print_Server
{
Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node XOAP_Citrix_Universal_Print_Server
    {
        WindowsFeature 'Print-Services'
        {
            Name    = 'Print-Services'
            Ensure  = 'Present'
        }
        
        WindowsFeature 'Print-Server'
        {
            Name    = 'Print-Server'
            Ensure  = 'Present'
        }
    }
}
XOAP_Citrix_Universal_Print_Server