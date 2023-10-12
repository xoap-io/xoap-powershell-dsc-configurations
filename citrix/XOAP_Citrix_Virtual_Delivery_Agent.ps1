Configuration 'XOAP_Citrix_Virtual_Delivery_Agent'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'XOAP_Citrix_Virtual_Delivery_Agent'
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
