Configuration 'xoap-w10-1909-developer-vdi'
{

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DSCResource -ModuleName AuditPolicyDSC
    Import-DSCResource -ModuleName PowerShellAccessControl
    Import-DSCResource -ModuleName WindowsDefender
    Import-DscResource -ModuleName cNtfsAccessControl
    Import-DscResource -ModuleName xPrinterManagement
    Import-DscResource -ModuleName OneDriveDsc
    Import-DscResource -ModuleName PendingReboot
    Import-DscResource -ModuleName XOAPBaselineModuleDSC
    Import-DSCResource -ModuleName XOAPVdiOptimizeW10Ent1909EnDSC
    Import-DscResource -ModuleName XOAPLCMDefaultsDSC
    Import-DSCResource -ModuleName RISBaselineDSC

    Node "xoap-w10-1909-developer-vdi"
    {
        # 00 Configuration_Defaults
        cNtfsPermissionEntry PermissionSet1
        {
            Ensure = 'Present'
            Path = "C:\Windows\Temp"
            Principal = "S-1-1-0"
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'ReadAndExecute'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
        }

        # 01_ActiveSetup
        # DOTNETFRAMEWORKS
        Registry "89B4C1CD-B018-4511-B0A1-5476DBF70820"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"
            Ensure = "Absent"
        }


        # DOTNETFRAMEWORKS
        Registry "89B4C1CD-B018-4511-B0A1-5476DBF70820 x64"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"
            Ensure = "Absent"
        }

        # Microsoft Internet Explorer Initializer Setup
        Registry "89820200-ECBD-11cf-8B85-00AA005B4383"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89820200-ECBD-11cf-8B85-00AA005B4383}"
            Ensure = "Absent"
        }

        # Microsoft Outlook MailNews Express Setup -x64
        Registry "44BBA840-CC51-11CF-AAFA-00AA00B6015C"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{44BBA840-CC51-11CF-AAFA-00AA00B6015C}"
            Ensure = "Absent"
        }

        # Themes Setup
        Registry "2C7339CF-2B09-4501-B3F3-F3508C9228ED"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{2C7339CF-2B09-4501-B3F3-F3508C9228ED}"
            Ensure = "Absent"
        }

        # Windows Desktop Update Setup
        Registry "89820200-ECBD-11cf-8B85-00AA005B4340"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{89820200-ECBD-11cf-8B85-00AA005B4340}"
            Ensure = "Absent"
        }

        # Windows Windows Media Player
        Registry "6BF52A52-394A-11d3-B153-00C04F79FAA6"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{6BF52A52-394A-11d3-B153-00C04F79FAA6}"
            Ensure = "Absent"
        }

        # Windows Media Player
        Registry "22d6f312-b0f6-11d0-94ab-0080c74c7e95"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\"
            ValueName = "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}"
            Ensure = "Absent"
        }

        # Windows Media Player -x64
        Registry "22d6f312-b0f6-11d0-94ab-0080c74c7e95 x64"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{22d6f312-b0f6-11d0-94ab-0080c74c7e95}"
            Ensure = "Absent"
        }

        # IE ESC for Admins
        Registry "A509B1A8-37EF-4b3f-8CFC-4F3A74704073"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure = "Absent"
        }

        # IE ESC for Users
        Registry "A509B1A8-37EF-4b3f-8CFC-4F3A74704073 x64"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure = "Absent"
        }

        # StubPath
        Registry "2D46B6DC-2207-486B-B523-A557E6D54B47"
        {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\"
            ValueName = "{2D46B6DC-2207-486B-B523-A557E6D54B47}"
            Ensure = "Absent"
        }

         # 02_IExplorer
         Registry DisableIEFirstRun
         {
             Key               = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InternetExplorer\Main"
             Ensure            = "Present"
             ValueName         = "DisableFirstRunCustomize"
             ValueType         = "Dword"
             ValueData        = "00000001"
         }

         #Reduce Internet Explorer Temp File
         Registry IETempPath
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths"
             Ensure          = "Present"
             ValueName       = "Paths"
             ValueType       = "Dword"
             ValueData       = "000000004"
         }

         #Reduce Internet Explorer Temp File
         Registry IETempPath1
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path1"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         #Reduce Internet Explorer Temp File
         Registry "IETempPath2"
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path2"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         #Reduce Internet Explorer Temp File
         Registry "IETempPath3"
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path3"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         #Reduce Internet Explorer Temp File
         Registry "IETempPath4"
         {
             Key             = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\path4"
             Ensure          = "Present"
             ValueName       = "CacheLimit"
             ValueType       = "Dword"
             ValueData       = "000000100"
         }

         # 03_SecPol
         # Disable customer experience improvement program
         Registry DisableCEIP
         {
             Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\SQMClient\Windows\"
             Ensure      = "Present"
             ValueName   = "CEIPEnable"
             ValueType   = "dword"
             ValueData   = "0"
         }

         # Disable Windows Defender
         Registry DisableWindowsDefender
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
             Ensure      = "Present"
             ValueName   = "Real-Time Protection"
             ValueType   = "dword"
             ValueData   = "1"
         }

         # Disable Anti Spyware
         Registry DisableAntiSpyWare
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware"
             Ensure      = "Present"
             ValueName   = "DisableAntiSpyware"
             ValueType   = "dword"
             ValueData   = "1"
         }

         # Location based info in searches
         Registry DisableLocation
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
             Ensure      = "Present"
             ValueName   = "AllowSearchToUseLocation"
             ValueType   = "dword"
             ValueData   = "00000000"
         }

         # Disable search web when searching pc
         Registry DisableSearchWeb
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
             Ensure      = "Present"
             ValueName   = "ConnectedSearchUseWeb"
             ValueType   = "dword"
             ValueData   = "00000000"
         }

         # Disable send additional info with error reports
         Registry DisableAdditionalInfoErrorReports
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
             Ensure      = "Present"
             ValueName   = "DontSendAdditionalData"
             ValueType   = "dword"
             ValueData   = "00000001"
         }

         # Lock Workstation after 10 minutes
         Registry InactivityTimeoutSecs
         {
             Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
             Ensure      = "Present"
             ValueName   = "InactivityTimeoutSecs"
             ValueType   = "dword"
             ValueData   = "00000600"
         }


         # 04_Networking
         # Disable Network Location
         Registry DisableNetworkLocation
         {
             Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Network"
             Ensure      = "Present"
             ValueName   = "NewNetworkWindowOff"
             ValueType   = "dword"
             ValueData   = "1"
         }

         # Disable TCP/IP Task Offload
         Registry DisableTCPTaskOffload
         {
             Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters\"
             Ensure      = "Present"
             ValueName   = "DisableTaskOffload"
             ValueType   = "dword"
             ValueData   = "1"
         }


         # 05_ScheduledTasks
         ScheduledTask "SmartScreenSpecific"
         {
             TaskName = "SmartScreenSpecific"
             TaskPath = "\Microsoft\Windows\AppID\"
             Ensure = 'Absent'
         }

         ScheduledTask "MicrosoftCompatibilityAppraiser"
         {
             TaskName = "Microsoft Compatibility Appraiser"
             TaskPath = "\Microsoft\Windows\Application Experience\"
             Ensure = 'Absent'
         }

         ScheduledTask "ProgramDataUpdater"
         {
             TaskName = "ProgramDataUpdater"
             TaskPath = "\Microsoft\Windows\Application Experience\"
             Ensure = 'Absent'
         }

         ScheduledTask "StartupAppTask"
         {
             TaskName = "StartupAppTask"
             TaskPath = "\Microsoft\Windows\Application Experience\"
             Ensure = 'Absent'
         }

         ScheduledTask Proxy
         {
             TaskName = "Proxy"
             TaskPath = "\Microsoft\Windows\Autochk\"
             Ensure = 'Absent'
         }

         ScheduledTask "UninstallDeviceTask"
         {
             TaskName = "UninstallDeviceTask"
             TaskPath = "\Microsoft\Windows\Bluetooth\"
             Ensure = 'Absent'
         }

         ScheduledTask "ProactiveScan"
         {
             TaskName = "ProactiveScan"
             TaskPath = "\Microsoft\Windows\Chkdsk\"
             Ensure = 'Absent'
         }

         ScheduledTask "CreateObjectTask"
         {
             TaskName = "CreateObjectTask"
             TaskPath = "\Microsoft\Windows\CloudExperienceHost\"
             Ensure = 'Absent'
         }

         ScheduledTask "Consolidator"
         {
             TaskName = "Consolidator"
             TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
             Ensure = 'Absent'
         }

         ScheduledTask "KernelCeipTask"
         {
             TaskName = "KernelCeipTask"
             TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
             Ensure = 'Absent'
         }

         ScheduledTask "UsbCeip"
         {
             TaskName = "UsbCeip"
             TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"
             Ensure = 'Absent'
         }

         ScheduledTask "ScheduledDefrag"
         {
             TaskName = "ScheduledDefrag"
             TaskPath = "\Microsoft\Windows\Defrag\"
             Ensure = 'Absent'
         }

         ScheduledTask "Scheduled"
         {
             TaskName = "Scheduled"
             TaskPath = "\Microsoft\Windows\Diagnosis\"
             Ensure = 'Absent'
         }

         ScheduledTask "Microsoft-Windows-DiskDiagnosticDataCollector"
         {
             TaskName = "Microsoft-Windows-DiskDiagnosticDataCollector"
             TaskPath = "\Microsoft\Windows\DiskDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "Microsoft-Windows-DiskDiagnosticResolver"
         {
             TaskName = "Microsoft-Windows-DiskDiagnosticResolver"
             TaskPath = "\Microsoft\Windows\DiskDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "DmClient"
         {
             TaskName = "DmClient"
             TaskPath = "\Microsoft\Windows\Feedback\Siuf\"
             Ensure = 'Absent'
         }

         # ScheduledTask "FileHistory"
         # {
         #     TaskName = "File History (maintenance mode)"
         #     TaskPath = "\Microsoft\Windows\FileHistory\"
         #     Enable = $true
         # }

         # ScheduledTask "Notifications"
         # {
         #     TaskName = "Notifications"
         #     TaskPath = "\Microsoft\Windows\Location\"
         #     Enable = $true
         # }

         ScheduledTask "WinSAT"
         {
             TaskName = "WinSAT"
             TaskPath = "\Microsoft\Windows\Maintenance\"
             Ensure = 'Absent'
         }

         ScheduledTask "MapsToastTask"
         {
             TaskName = "MapsToastTask"
             TaskPath = "\Microsoft\Windows\Maps\"
             Ensure = 'Absent'
         }

         ScheduledTask "MapsUpdateTask"
         {
             TaskName = "MapsUpdateTask"
             TaskPath = "\Microsoft\Windows\Maps\"
             Ensure = 'Absent'
         }

         ScheduledTask "ProcessMemoryDiagnosticEvents"
         {
             TaskName = "ProcessMemoryDiagnosticEvents"
             TaskPath = "\Microsoft\Windows\MemoryDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "RunFullMemoryDiagnostic"
         {
             TaskName = "RunFullMemoryDiagnostic"
             TaskPath = "\Microsoft\Windows\MemoryDiagnostic\"
             Ensure = 'Absent'
         }

         ScheduledTask "MNOMetadataParse"
         {
             TaskName = "MNO Metadata Parser"
             TaskPath = "\Microsoft\Windows\Mobile Broadband Accounts\"
             Ensure = 'Absent'
         }

         ScheduledTask "AnalyzeSystem"
         {
             TaskName = "AnalyzeSystem"
             TaskPath = "\Microsoft\Windows\Power Efficiency Diagnostics\"
             Ensure = 'Absent'
         }

         ScheduledTask "MobilityManager"
         {
             TaskName = "MobilityManager"
             TaskPath = "\Microsoft\Windows\Ras\"
             Ensure = 'Absent'
         }

         ScheduledTask "RegIdleBackup"
         {
             TaskName = "RegIdleBackup"
             TaskPath = "\Microsoft\Windows\Registry\"
             Ensure = 'Absent'
         }

         ScheduledTask "FamilySafetyMonitor"
         {
             TaskName = "FamilySafetyMonitor"
             TaskPath = "\Microsoft\Windows\Shell\"
             Ensure = 'Absent'
         }

         ScheduledTask "FamilySafetyRefresh"
         {
             TaskName = "FamilySafetyRefreshTask"
             TaskPath = "\Microsoft\Windows\Shell\"
             Ensure = 'Absent'
         }

         ScheduledTask "SR"
         {
             TaskName = "SR"
             TaskPath = "\Microsoft\Windows\SystemRestore\"
             Ensure = 'Absent'
         }

         ScheduledTask "Tpm-Maintenance"
         {
             TaskName = "Tpm-Maintenance"
             TaskPath = "\Microsoft\Windows\TPM\"
             Ensure = 'Absent'
         }

         ScheduledTask "UPnPHostConfig"
         {
             TaskName = "UPnPHostConfig"
             TaskPath = "\Microsoft\Windows\UPnP\"
             Ensure = 'Absent'
         }

         # ScheduledTask "ResolutionHost"
         # {
         #     TaskName = "ResolutionHost"
         #     TaskPath = "\Microsoft\Windows\WDI\"
         #     Ensure = 'Absent'
         # }

         ScheduledTask "WindowsDefenderCacheMaintenance"
         {
             TaskName = "Windows Defender Cache Maintenance"
             TaskPath = "\Microsoft\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderCleanup"
         {
             TaskName = "Windows Defender Cleanup"
             TaskPath = "\Microsoft\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderScheduledScan"
         {
             TaskName = "Windows Defender Scheduled Scan"
             TaskPath = "\Microsoft\Windows\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "WindowsDefenderVerification"
         {
             TaskName = "Windows Defender Verification"
             TaskPath = "\Microsoft\Windows\Windows Defender\"
             Ensure = 'Absent'
         }

         ScheduledTask "QueueReporting"
         {
             TaskName = "QueueReporting"
             TaskPath = "\Microsoft\Windows\Windows Error Reporting\"
             Ensure = 'Absent'
         }

         ScheduledTask "BfeonServiceStartTypeChange"
         {
             TaskName = "BfeonServiceStartTypeChange"
             TaskPath = "\Microsoft\Windows\Windows Filtering Platform\"
             Ensure = 'Absent'
         }

         ScheduledTask "UpdateLibrary"
         {
             TaskName = "UpdateLibrary"
             TaskPath = "\Microsoft\Windows\Windows Media Sharing\"
             Ensure = 'Absent'
         }

         ScheduledTask "WIM-Hash-Management"
         {
             TaskName = "WIM-Hash-Management"
             TaskPath = "\Microsoft\Windows\WOF\"
             Ensure = 'Absent'
         }

         ScheduledTask "WIM-Hash-Validation"
         {
             TaskName = "WIM-Hash-Validation"
             TaskPath = "\Microsoft\Windows\WOF\"
             Ensure = 'Absent'
         }

         ScheduledTask "XblGameSaveTask"
         {
             TaskName = "XblGameSaveTask"
             TaskPath = "\Microsoft\XblGameSave\"
             Ensure = 'Absent'
         }

         ScheduledTask "XblGameSaveTaskLogon"
         {
             TaskName = "XblGameSaveTaskLogon"
             TaskPath = "\Microsoft\XblGameSave\"
             Ensure = 'Absent'
         }




        # 06_Services
        # Increase services startup timeout from 30 to 45 seconds
        Registry IncreaseServicesStartupTimeout
        {
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control"
            Ensure      = "Present"
            ValueName   = "ServicesPipeTimeout"
            ValueType   = "Dword"
            ValueData   = "120000"
        }

        #Disabling AllJoyn Router service
        Service AJRouter
        {
            Name        = "AJRouter"
            State       = "stopped"
            StartupType = "Disabled"
        }

        #Disabling Application Layer Gateway service
        Service ALG
        {
            Name        = "ALG"
            State       = "stopped"
            StartupType = "Disabled"
        }

        #Disabling Background Intelligent Transfer service
        Service "BITS"
        {
            Name        = "BITS"
            State       = "stopped"
            StartupType = "Manual"
        }

        #Branche Cache service
        Service "PeerDistSvc"
        {
            Name        = "PeerDistSvc"
            State       = "stopped"
            StartupType = "Disabled"
        }

        #Disabling Device Association Service
        # Service "DeviceAssociationService"
        # {
        # Name        = "DeviceAssociationService"
        # State       = "stopped"
        # StartupType = "Disabled"
        # }

        #Disabling Diagnostic Policy service
        Service "DPS"
        {
        Name        = "DPS"
        State       = "stopped"
        #StartupType = "Disabled"
        }

        #Disabling Diagnostic service Host service
        Service "WdiServiceHost"
        {
        Name        = "WdiServiceHost"
        State       = "stopped"
        StartupType = "Disabled"
        }

        #Disabling Diagnostic System Host service
        Service "WdiSystemHost"
        {
        Name        = "WdiSystemHost"
        State       = "stopped"
        #StartupType = "Disabled"
        }

        #Connected User Experiences and Telemetry
        Service "DiagTrack"
        {
        Name        = "DiagTrack"
        State       = "stopped"
        #StartupType = "Disabled"
        }

        #Disabling Fax service
        # Service "Fax"
        # {
        #     Name        = "Fax"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        #Disabling Function Discovery Provider Host service
        Service "fdPHost"
        {
            Name        = "fdPHost"
            State       = "stopped"
            StartupType = "Disabled"
        }

        #Disabling Function Discovery Resource Publication service
        Service "FDResPub"
        {
        Name        = "FDResPub"
        State       = "stopped"
        StartupType = "Disabled"
        }

        #Disabling Home Group Listener service
        # Service "HomeGroupListener"
        # {
        #     Name        = "HomeGroupListener"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        #Disabling Internet Connection Sharing (ICS) service
        Service "SharedAccess"
        {
            Name        = "SharedAccess"
            State       = "stopped"
            StartupType = "Disabled"
        }

        # #Disabling Infrared Monitoring service
        # Service "irmon"
        # {
        #     Name        = "irmon"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }


        # Disabling Microsoft Maps Download Manager service
        Service MapsBroker
        {
            Name        = "MapsBroker"
            State       = "stopped"
            #StartupType = "Disabled"
        }


        #Disabling Offline Files service
        Service "CscService"
        {
            Name        = "CscService"
            State       = "stopped"
           #StartupType = "Disabled"
        }


        #Disabling Retail Demo service
        Service "RetailDemo"
        {
            Name        = "RetailDemo"
            State       = "stopped"
            StartupType = "Disabled"
        }

        #Disabling Security service
        # Service "wscsvc"
        # {
        #     Name        = "wscsvc"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        #Disabling Sensor Monitoring service
        Service "SensrSvc"
        {
            Name        = "SensrSvc"
            State       = "stopped"
            StartupType = "Disabled"
        }


        #Disabling UPnP Device Host service
        Service "upnphost"
        {
            Name        = "upnphost"
            State       = "stopped"
            StartupType = "Disabled"
        }


        #Disabling Windows Connect Now - Config Registrar service
        Service "wcncsvc"
        {
            Name        = "wcncsvc"
            State       = "stopped"
            StartupType = "Disabled"
        }

        #Disabling Windows Error Reporting service
        Service "WerSvc"
        {
            Name        = "WerSvc"
            State       = "stopped"
            #StartupType = "Disabled"
        }

        #Disabling Windows Media Player Network Sharing service
        Service "WMPNetworkSvc"
        {
            Name        = "WMPNetworkSvc"
            State       = "stopped"
            StartupType = "Disabled"
        }


        #Disabling Windows Mobile Hotspot service
        Service "icssvc"
        {
            Name        = "icssvc"
            State       = "stopped"
            #StartupType = "Disabled"
        }


        # GameDVR and Broadcast User Service
        # Service "BcastDVRUserService"
        # {
        #     Name        = "BcastDVRUserService"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        # CaptureService
        # Service "CaptureService"
        # {
        #     Name        = "CaptureService"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        # DevicePickerUserSvc
        # Service "DevicePicker"
        # {
        #     Name        = "DevicePicker"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        # DevicesFlowUserSvc
        # Service "DevicesFlow"
        # {
        #     Name        = "DevicesFlow"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        # # MessagingService
        # Service "MessagingService"
        # {
        #     Name        = "MessagingService"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        # # PrintWorkflowUserSvc
        # Service "PrintWorkflow"
        # {
        #     Name        = "PrintWorkflow"
        #     State       = "stopped"
        #     StartupType = "Disabled"
        # }

        # 09_Optimisation
        Registry DisableFirstLogonAnimation
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Ensure      = "Present"
            ValueName   = "EnableFirstLogonAnimation"
            ValueType   = "Dword"
            ValueData   = "00000000"
        }

        # Hide Hard Error Messages
        Registry DisableHardErrorMessages
        {
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Windows"
            Ensure      = "Present"
            ValueName   = "ErrorMode"
            ValueType   = "Dword"
            ValueData   = "00000002"
        }

        # Disable Memory Dump Creation
        Registry DisableDump
        {
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\CrashControl"
            Ensure      = "Present"
            ValueName   = "CrashDumpEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }
        # Disable Background Auto-Layout
        Registry DefragBootOptimizeFunction
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout"
            Ensure      = "Present"
            ValueName   = "EnableAutoLayout"
            ValueType   = "Dword"
            ValueData   = "00000000"
        }

        # Increase Disk I/O Timeout to 200 seconds
        Registry IncreaseDiskIOTimeout
        {
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk"
            Ensure      = "Present"
            ValueName   = "TimeOutValue"
            ValueType   = "Dword"
            ValueData   = "200"
        }

        # Keep drivers and kernel on physical memory
        Registry MemoryManagement
        {
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management"
            Ensure      = "Present"
            ValueName   = "DisablePagingExecutive"
            ValueType   = "Dword"
            ValueData   = "00000001"
        }

        ## Telemetrie - Chrome

        Registry RecommendedMetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\Recommended"
            Ensure      = "Present"
            ValueName   = "MetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry MetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\"
            Ensure      = "Present"
            ValueName   = "MetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry RecommendedDeviceMetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\Recommended"
            Ensure      = "Present"
            ValueName   = "DeviceMetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry DeviceMetricsReportingEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\"
            Ensure      = "Present"
            ValueName   = "DeviceMetricsReportingEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }


        # Appx Paackages
        Registry DisableWindowsConsumerFeatures
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "DisableWindowsConsumerFeatures"
            ValueType   = "dword"
            ValueData   = "00000001"
        }

        Registry ContentDeliveryAllowed
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "ContentDeliveryAllowed"
            ValueType   = "dword"
            ValueData   = "00000000"
        }


        Registry OemPreInstalledAppsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "OemPreInstalledAppsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry PreInstalledAppsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "PreInstalledAppsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry PreInstalledAppsEverEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "PreInstalledAppsEverEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        Registry SilentInstalledAppsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "SilentInstalledAppsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }
        Registry SystemPaneSuggestionsEnabled
        {
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Ensure      = "Present"
            ValueName   = "SystemPaneSuggestionsEnabled"
            ValueType   = "dword"
            ValueData   = "00000000"
        }

        ## Windows Telemetry
        Registry DisableTelemetryCollection
        {
            ValueName   = "AllowTelemetry"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry DisableSensors
        {
            ValueName   = "DisableSensors"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
            ValueType   = "dword"
            ValueData   = "1"
        }


        ## IE Tracking

        Registry DoNotTrack
        {
            ValueName   = "DoNotTrack"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\Main"
            ValueType   = "dword"
            ValueData   = "1"
        }

        # Registry PreventLiveTileDataCollection
        {
            ValueName   = "PreventLiveTileDataCollection"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\Main"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry EnableExtendedBooksTelemetry
        {
            ValueName   = "EnableExtendedBooksTelemetry"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry MicrosoftEdgeDataOptIn
        {
            ValueName   = "MicrosoftEdgeDataOptIn"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Maps
        Registry MapsAutoUpdate
        {
            ValueName   = "AutoUpdateEnabled"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\System\Maps"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable AutoLogger-Diagtrack-Listener
        Registry AutoLoggerDiagtrackListener
        {
            ValueName   = "Start"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable Authenticated Proxy usage
        Registry 'DisableEnterpriseAuthProxy'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueName = 'DisableEnterpriseAuthProxy'
            ValueType = 'DWord'
            ValueData = '1'
        }

        #Firefox telemetry
        Registry 'FirefoxDisableTelemetry'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'DisableTelemetry'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'BlockAboutConfig'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'BlockAboutConfig'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'BlockAboutProfiles'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'BlockAboutProfiles'
            ValueType = 'DWord'
            ValueData = '1'
        }

        Registry 'DontCheckDefaultBrowser'
        {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox'
            ValueName = 'DontCheckDefaultBrowser'
            ValueType = 'DWord'
            ValueData = '1'
        }


        # 10_MSOfficeSettings
        #Disable SharedComputerLicensing
        Registry OfficeSharedComputerLicensing
        {
            ValueName   = "SharedComputerLicensing"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
            ValueType   = "String"
            ValueData   = "0"
        }


        #Disable feedback in Office
        Registry FeedbackEnabled
        {
            ValueName   = "Enabled"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry includescreenshot
        {
            ValueName   = "includescreenshot"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback"
            ValueType   = "dword"
            ValueData   = "0"
        }


        #Disable data collection and telemetry in Office
        Registry notrack
        {
            ValueName   = "notrack"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\general"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry optindisable
        {
            ValueName   = "optindisable"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\general"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry shownfirstrunoptin
        {
            ValueName   = "shownfirstrunoptin"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\general"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry ptwoptin
        {
            ValueName   = "ptwoptin"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry bootedrtm
        {
            ValueName   = "bootedrtm"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\firstrun"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry disablemovie
        {
            ValueName   = "disablemovie"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\firstrun"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry enablefileobfuscation
        {
            ValueName   = "enablefileobfuscation"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry enablelogging
        {
            ValueName   = "enablelogging"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry accesssolution
        {
            ValueName   = "accesssolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }


        Registry olksolution
        {
            ValueName   = "olksolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry onenotesolution
        {
            ValueName   = "onenotesolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry pptsolution
        {
            ValueName   = "pptsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry Projectsolution
        {
            ValueName   = "projectsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry publishersolution
        {
            ValueName   = "publishersolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry visiosolution
        {
            ValueName   = "visiosolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry wdsolution
        {
            ValueName   = "wdsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry xlsolution
        {
            ValueName   = "xlsolution"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry agave
        {
            ValueName   = "agave"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry appaddins
        {
            ValueName   = "appaddins"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry comaddins
        {
            ValueName   = "comaddins"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry documentfiles
        {
            ValueName   = "documentfiles"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry templatefiles
        {
            ValueName   = "templatefiles"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes"
            ValueType   = "dword"
            ValueData   = "1"
        }

        #Disable online repair in Office
        Registry onlinerepair
        {
            ValueName   = "onlinerepair"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry fallbacktocdn
        {
            ValueName   = "fallbacktocdn"
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable Outlook logging
        Registry OutlookEnableLogging
        {
            ValueName   = "EnableLogging"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Options\Mail"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable Word logging
        Registry WordEnableLogging
        {
            ValueName   = "EnableLogging"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Options"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #Disable Office Client Telemetry
        Registry DisableClientTelemetry
        {
            ValueName   = "DisableTelemetry"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Microsoft\Office\Common\ClientTelemetry"
            ValueType   = "dword"
            ValueData   = "1"
        }

        #Common Office Policies
        Registry disableboottoofficestart
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry qmenable
        {
            ValueName   = "qmenable"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry sendcustomerdata
        {
            ValueName   = "sendcustomerdata"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "0"
        }

        Registry updatereliabilitydata
        {
            ValueName   = "updatereliabilitydata"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #General Office Policies
        Registry disableboottoofficestartGeneral
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\General"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry ShownFileFmtPrompt
        {
            ValueName   = "ShownFileFmtPrompt"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\General"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #General Office Policies
        Registry disableboottoofficestartInternet
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Internet"
            ValueType   = "dword"
            ValueData   = "1"
        }

        Registry serviceleveloptions
        {
            ValueName   = "serviceleveloptions"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Internet"
            ValueType   = "dword"
            ValueData   = "0"
        }

        #PTWatson Office Policies
        Registry disableboottoofficestartPTWatson
        {
            ValueName   = "disableboottoofficestart"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\PTWatson"
            ValueType   = "dword"
            ValueData   = "1"
        }

        #File validation Office Policies
        Registry disablereporting
        {
            ValueName   = "disablereporting"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Security\FileValidation"
            ValueType   = "dword"
            ValueData   = "1"
        }

        #Lync Office
        Registry disableautomaticsendtracing
        {
            ValueName   = "disableautomaticsendtracing"
            Ensure      = "Present"
            Key         = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Lync"
            ValueType   = "dword"
            ValueData   = "1"
        }


        # 11_Powercfg_and_InstallPowershellModules
        Script "powercfg"{
            TestScript = {
                $x =  Get-WmiObject -Class Win32_Powerplan -Namespace root\CIMV2\Power
                $y = $x.InstanceID
                [bool]$t = $true
                foreach($s in $y){
                $a1 = powercfg -Query $($s.Split("{}")[1]) SUB_SLEEP STANDBYIDLE
                $b1 = $a1 | Select-Object -Last 3
                $c1 = $b1 | Select-Object -First 2
                $z1_1 = $c1.Split(":")[1] -eq " 0x00000000"
                $z1_2 = $c1.Split(":")[3] -eq " 0x00000000"

                $a2 = powercfg -Query $($s.Split("{}")[1]) SUB_VIDEO VIDEOIDLE
                $b2 = $a2 | Select-Object -Last 3
                $c2 = $b2 | Select-Object -First 2
                $z2_1 = $c2.Split(":")[1] -eq " 0x00000708"
                $z2_2 = $c2.Split(":")[3] -eq " 0x00000708"

                $a3 = powercfg -Query $($s.Split("{}")[1]) SUB_DISK DISKIDLE
                $b3 = $a3 | Select-Object -Last 3
                $c3 = $b3 | Select-Object -First 2
                $z3_1 = $c3.Split(":")[1] -eq " 0x00000000"
                $z3_2 = $c3.Split(":")[3] -eq " 0x00000000"

                $a4 = powercfg -Query $($s.Split("{}")[1]) SUB_SLEEP HIBERNATEIDLE
                $b4 = $a4 | Select-Object -Last 3
                $c4 = $b4 | Select-Object -First 2
                $z4_1 = $c4.Split(":")[1] -eq " 0x00000000"
                $z4_2 = $c4.Split(":")[3] -eq " 0x00000000"

                $t = $z1_1 -and $z1_2 -and $z2_1 -and $z2_2 -and $z3_1 -and $z3_2 -and $z4_1 -and $z4_2  -and $t
                            }
                $t
                    }
            SetScript = {
                $activescheme = powercfg /getactivescheme
                $schemestemp = powercfg -l
                $schemes = $schemestemp | select-object -skip 3

                foreach($s in $schemes){
                    Write-Output "Power Configuration $($s.Split( )[5,6]) will be set to Never sleep."
                    powercfg /setactive $s.Split( )[3]
                    powercfg /change monitor-timeout-ac 30
                    powercfg /change monitor-timeout-dc 30
                    powercfg /change disk-timeout-ac 0
                    powercfg /change disk-timeout-dc 0
                    powercfg /change standby-timeout-ac 0
                    powercfg /change standby-timeout-dc 0
                    powercfg /change hibernate-timeout-ac 0
                    powercfg /change hibernate-timeout-dc 0
                         }
                powercfg /setactive $activescheme.Split( )[3]
                    }
            GetScript = {
                    }
        }

        Script "InstallPowershellModules"{
            TestScript = {
            $t1 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\AzureRM"
            $t2 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\AzureAD"
            $t3 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\Microsoft.Online.SharePoint.PowerShell"
            $t4 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\PendingReboot"
            $t5 = test-path -Path "C:\Program Files\WindowsPowerShell\Modules\BurntToast"

            [bool]$t = $true
            $t= $t1 -and $t2 -and $t3 -and $t4 -and $t5
            $t
            }

            SetScript = {
            Install-Module -Name AzureAD -AllowClobber
            Install-Module -Name AzureRM -AllowClobber
            Install-Module -Name Microsoft.Online.SharePoint.PowerShell -AllowClobber
            Install-Module -Name PendingReboot -AllowClobber
            Install-Module -Name BurntToast -AllowClobber
                    }

            GetScript = {
                    }
        }


        # 12_Deactivate_guest_access
        SecurityOption AccountSecurityOptions {
            Name = 'AccountSecurityOptions'
        Accounts_Guest_account_status = 'Disabled'
             }

        Registry 'AllowInsecureGuestAuth' {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName = 'AllowInsecureGuestAuth'
            ValueType = 'DWord'
            ValueData = '0'
        }

        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy   = 'Deny_access_to_this_computer_from_the_network'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonasabatchjob {
            Policy   = 'Deny_log_on_as_a_batch_job'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonasaservice {
            Policy   = 'Deny_log_on_as_a_service'
            Identity = 'Guests'
        }

        UserRightsAssignment Denylogonlocally {
            Policy   = 'Deny_log_on_locally'
            Identity = 'Guests'
        }

        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy   = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity = 'Guests'
        }


        # # 13_Activate_BitLocker
        # Script "BitLocker"{
        #     TestScript = {
        #         [bool]$t1 = $true
        #         [bool]$t2 = $true
        #         $t1=(Get-WmiObject -Class win32_tpm -Namespace root\cimv2\Security\MicrosoftTpm).IsActivated().IsActivated
        #         $obj=gwmi("Win32_EncryptableVolume") -namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" |where VolumeType -eq 0
        #         $t2=[Boolean]$obj.ProtectionStatus
        #         if(-not $t2 -and $t1){
        #             [bool]$t = $False
        #             }
        #         else{
        #             [bool]$t = $true
        #             }
        #         $t
        #         }

        #     SetScript = {
        #         $obj=gwmi("Win32_EncryptableVolume") -namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" |where VolumeType -eq 0
        #         Add-BitLockerKeyProtector -MountPoint $obj.DriveLetter -RecoveryPasswordProtector
        #         $BLV = Get-BitLockerVolume -MountPoint $obj.DriveLetter
        #         BackupToAAD-BitLockerKeyProtector -MountPoint $obj.DriveLetter -KeyProtectorId $BLV.KeyProtector[0].KeyProtectorId
        #         Enable-BitLocker -MountPoint $obj.DriveLetter -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
        #         }

        #     GetScript = {
        #         }
        # }


        # # 14_Driver_Installation
        # xPrinterDriver HPLaserjetPRO400M475dn
        # {
        #     DriverName = "HP LJ300-400 color MFP M375-M475 PCL6 Class Driver"
        #     Ensure = "Present"

        # }


        # 15_OneDrive_Activation_and_Configuration
        #Enable auto log on with currently signed Azure AD user
        OneDrive RISCAccountConfig {

            FilesOnDemandEnabled = 'Present'
            SilentAccountConfig = 'Present'

        }


        # # 16_Add_User_to_Hyper-V_Admins
        # Script "Add_User_to_Hyper-V_Admins"{
        #     TestScript = {
        #         $hyper_v = (Get-WindowsOptionalFeature -online -FeatureName "Microsoft-hyper-v").state
        #         $current_user = Get-WmiObject Win32_ComputerSystem | Select -ExpandProperty UserName
        #         $hyper_v_admins_sid = 'S-1-5-32-578'
        #         $members = @(Get-LocalGroupMember -SID $hyper_v_admins_sid)
        #         $X=$members | Select-String $current_user -SimpleMatch
        #         if($hyper_v -eq 'Enabled' -and !([bool]$X)){
        #             [bool]$t = $False
        #         }
        #         elseif($hyper_v -eq 'Enabled' -and [bool]$X){
        #             Write-Verbose "$current_user is already a Hyper-V administrator"
        #             [bool]$t = $true
        #         }
        #         Else{
        #             Write-Verbose "Hyper-V is disabled"
        #             [bool]$t = $true
        #         }
        #         $t
        #         }

        #     SetScript = {
        #             $current_user = Get-WmiObject Win32_ComputerSystem | Select -ExpandProperty UserName
        #             $hyper_v_admins_sid = 'S-1-5-32-578'
        #             Add-LocalGroupMember -SID $hyper_v_admins_sid -Member $current_user
        #             Write-Verbose "$current_user is now a Hyper-V administrator"
        #             }

        #     GetScript = {
        #         }
        # }

        # 17 Vdi Optimisation
        XOAPVdiOptimizeMeta "XOAPVdiOptimizeW10Ent1909EnDSC Config" {
            Include_XOAPVdiOptimizeWindowsMediaPlayerRemoval = $true
            Include_XOAPVdiOptimizeAppxPackagesRemoval = $true
            Include_XOAPVdiOptimizeDisableScheduleTasks = $true
            Include_XOAPVdiOptimizeUninstallOneDrive = $true
            Include_XOAPVdiOptimizeServicesAutologgersDisable = $true
            Include_XOAPVdiOptimizeServicesDisable = $true
            Include_XOAPVdiOptimizeNetworkOptimization = $true
        }

        # 99_Change_LCM_Defaults
        #final set:Disable automatic reboot
        XOAPLCMDefaultsMeta "Disable RebootIfNeeded"
        {
            Disable_Reboot = $true
        }
     }
}