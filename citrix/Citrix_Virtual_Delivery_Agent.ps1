Configuration 'Citrix_Virtual_Delivery_Agent'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion '10.0.0'

    Node 'Citrix_Virtual_Delivery_Agent'
    {
        $features = @(
            'Remote-Desktop-Services',
            'RDS-RD-Server',
            'Server-Media-Foundation',
            'Remote-Assistance'
        )
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

        # VDA - Session reliability and timeouts
        Registry 'SessionReliabilityTimeout' {
            Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Citrix\ICA\SessionReliability'
            Ensure      = 'Present'
            ValueName   = 'SessionReliabilityTimeout'
            ValueType   = 'DWORD'
            ValueData   = 1800
        }

        # VDA - Auto Reconnect
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
    }
}
