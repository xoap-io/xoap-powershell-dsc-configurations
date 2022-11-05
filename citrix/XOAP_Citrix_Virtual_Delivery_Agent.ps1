
Configuration XOAP_Citrix_Virtual_Delivery_Agent
{
Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '8.5.0'
Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node XOAP_Citrix_Virtual_Delivery_Agent
    {
        WindowsFeature 'Remote-Desktop-Services'
        {
            Name    = 'Remote-Desktop-Services'
            Ensure  = 'Present'
        }
        
        WindowsFeature 'RDS-RD-Server'
        {
            Name    = 'RDS-RD-Server'
            Ensure  = 'Present'
        }

        WindowsFeature 'Server-Media-Foundation'
        {
            Name    = 'Server-Media-Foundation'
            Ensure  = 'Present'
        }

        WindowsFeature 'Remote-Assistance'
        {
            Name    = 'Remote-Assistance'
            Ensure  = 'Present'
        }
    }
}
XOAP_Citrix_Virtual_Delivery_Agent