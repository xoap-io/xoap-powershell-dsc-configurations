Configuration 'XOAP_Citrix_Universal_Print_Server'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'XOAP_Citrix_Universal_Print_Server'
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
