Configuration 'Citrix_Virtual_Delivery_Agent'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '9.0.0'

    Node 'Citrix_Virtual_Delivery_Agent'
    {
        $features = @('Remote-Desktop-Services','RDS-RD-Server','Server-Media-Foundation','Remote-Assistance')
        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = 'Present'
            }
        }

        # Ensure Remote Desktop Services service is running and set to automatic
        Service 'TermService' {
            Name        = 'TermService'
            State       = 'Running'
            StartupType = 'Automatic'
        }

        # Windows Server 2022 specific optimizations
        # Disable SMBv1
        Registry 'SMBv1' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            Ensure      = 'Present'
            ValueName   = 'SMB1'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Disable Defender if using 3rd party AV
        Registry 'DisableDefender' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
            Ensure      = 'Present'
            ValueName   = 'DisableAntiSpyware'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Telemetry
        Registry 'Telemetry' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            Ensure      = 'Present'
            ValueName   = 'AllowTelemetry'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Power Plan - High Performance
        Registry 'PowerPlan' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
            Ensure      = 'Present'
            ValueName   = 'ActivePowerScheme'
            ValueType   = 'String'
            ValueData   = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' # High Performance GUID
        }
        # Event Log - Limit log size
        Registry 'ApplicationLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }
        Registry 'SystemLogMaxSize' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System'
            Ensure      = 'Present'
            ValueName   = 'MaxSize'
            ValueType   = 'DWORD'
            ValueData   = 32768
        }
        # Network - TCP/IP tuning
        Registry 'TcpAutoTuning' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            Ensure      = 'Present'
            ValueName   = 'EnableTCPA'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Storage - Disable Storage Spaces Direct (if not used)
        Registry 'DisableS2D' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\S2D'
            Ensure      = 'Present'
            ValueName   = 'Start'
            ValueType   = 'DWORD'
            ValueData   = 4
        }
        # VDA - Session reliability and timeouts
        Registry 'SessionReliabilityTimeout' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\SessionReliability'
            Ensure      = 'Present'
            ValueName   = 'SessionReliabilityTimeout'
            ValueType   = 'DWORD'
            ValueData   = 1800
        }
        Registry 'AutoReconnectEnabled' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\SessionReliability'
            Ensure      = 'Present'
            ValueName   = 'AutoReconnectEnabled'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # VDA - Graphics performance (EDT/H.264)
        Registry 'GraphicsMode' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\Graphics'
            Ensure      = 'Present'
            ValueName   = 'UseVideoCodecForCompression'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # VDA - Clipboard redirection (optional, for security)
        Registry 'ClipboardRedirection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Clipboard'
            Ensure      = 'Present'
            ValueName   = 'AllowClipboardRedirection'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # VDA - Audio redirection (optional, for security)
        Registry 'AudioRedirection' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\Client\Audio'
            Ensure      = 'Present'
            ValueName   = 'AllowAudioRedirection'
            ValueType   = 'DWORD'
            ValueData   = 0
        }
        # Security - Harden LSA
        Registry 'RunAsPPL' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            Ensure      = 'Present'
            ValueName   = 'RunAsPPL'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        # Security - Credential Guard
        Registry 'EnableVirtualizationBasedSecurity' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'EnableVirtualizationBasedSecurity'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
        Registry 'RequirePlatformSecurityFeatures' {
            Key         = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard'
            Ensure      = 'Present'
            ValueName   = 'RequirePlatformSecurityFeatures'
            ValueType   = 'DWORD'
            ValueData   = 1
        }
    }
}
Citrix_Virtual_Delivery_Agent