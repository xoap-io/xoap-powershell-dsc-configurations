  configuration domain-controller-config
  {
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'
    Import-DscResource -ModuleName 'StorageDsc'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    $demoAdministrator = "demo\demoadmin"
    $domainCredential = Get-Credential -Username $demoAdministrator -Message "Please type the password for $DemoAdministrator user"
    $safeModeCredential = $domainCredential

    Node domain-controller-config
    {
      WindowsFeatureSet ADDSInstall
      {
        Ensure = 'Present'
        Name = "AD-Domain-Services","RSAT-AD-Tools","RSAT-AD-Tools","RSAT-ADDS","RSAT-AD-AdminCenter","RSAT-ADDS-Tools"
        IncludeAllSubFeature = $true
      }

      WaitforDisk Disk1
      {
        DiskId = 1
        RetryIntervalSec = 10
        RetryCount = 30
      }

      Disk DiskD
      {
        DiskId = 1
        AllowDestructive = $true
        ClearDisk = $true
        DriveLetter = 'D'
        DependsOn = '[WaitforDisk]Disk1'
      }

      PendingReboot BeforeDC
      {
        Name = 'BeforeDC'
        SkipCcmClientSDK = $true
        DependsOn = '[WindowsFeatureSet]ADDSInstall','[Disk]DiskD'
      }

      ADDomain Domain
      {
        DomainName = 'contoso.local'
        DomainNetBiosName = 'contoso'
        Credential = $domainCredential
        SafemodeAdministratorPassword = $safeModeCredential
        DatabasePath = 'D:\NTDS'
        LogPath = 'D:\NTDS'
        SysvolPath = 'D:\SYSVOL'
        DependsOn = '[WindowsFeatureSet]ADDSInstall','[Disk]DiskD','[PendingReboot]BeforeDC'
      }

      ADUser demodomainadmin
      {
        UserName = 'demoAdmin'
        Password = $domainCredential
        PasswordNeverExpires = $true
        ChangePasswordAtLogon = $false
        DomainName = 'contoso.local'
        DependsOn = "[ADDomain]Domain"
      }

      Registry DisableRDPNLA
      {
        Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        ValueName = 'UserAuthentication'
        ValueData = 0
        ValueType = 'Dword'
        Ensure = 'Present'
        DependsOn = '[ADDomain]Domain'
      }
    }
  }

$MyData =
@{
  AllNodes =
  @(
    @{
      NodeName = 'DomainControllerConfig'
      PsDscAllowPlainTextPassword = $true
      PsDscAllowDomainUser = $true
    }
  )
}
domain-controller-config -ConfigurationData $MyData
