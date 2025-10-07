Configuration RDS_Optimization_W2K19 {
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xRemoteDesktopSessionHost'
    Import-DscResource -ModuleName 'xRemoteDesktopSessionCollection'
    Import-DscResource -ModuleName 'xRemoteDesktopSessionDeployment'
    Import-DscResource -ModuleName 'xRegistry'

    Node localhost {
        # Install RDS Session Host Role
        WindowsFeature RDS_SessionHost {
            Name   = 'RDS-RD-Server'
            Ensure = 'Present'
        }

        # Install RDS Licensing Role
        WindowsFeature RDS_Licensing {
            Name   = 'RDS-Licensing'
            Ensure = 'Present'
        }

        # Set RDS Licensing Mode (Per User)
        xRemoteDesktopSessionHost LicensingMode {
            LicensingMode = 'PerUser'
            DependsOn     = '[WindowsFeature]RDS_SessionHost'
        }

        # Set RDS Licensing Server
        xRemoteDesktopSessionHost LicensingServer {
            LicensingServer = 'YOUR_LICENSING_SERVER_FQDN'
            DependsOn       = '[WindowsFeature]RDS_Licensing'
        }

        # Set session timeout (Idle: 30 min, Disconnect: 8 hours)
        xRegistry IdleTimeout {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            ValueName = 'IdleTimeout'
            ValueData = 1800000
            ValueType = 'Dword'
            Ensure    = 'Present'
        }
        xRegistry DisconnectTimeout {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            ValueName = 'DisconnectTimeout'
            ValueData = 28800000
            ValueType = 'Dword'
            Ensure    = 'Present'
        }

        # Set maximum sessions per user
        xRegistry MaxInstanceCount {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            ValueName = 'MaxInstanceCount'
            ValueData = 1
            ValueType = 'Dword'
            Ensure    = 'Present'
        }

        # Performance optimizations (example: disable wallpaper)
        xRegistry DisableWallpaper {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop'
            ValueName = 'NoChangingWallPaper'
            ValueData = 1
            ValueType = 'Dword'
            Ensure    = 'Present'
        }
            # Disable unnecessary services
            Service PrintSpooler {
                Name        = 'Spooler'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }
            Service WindowsSearch {
                Name        = 'WSearch'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }

            # Disable clipboard and drive redirection (Group Policy registry keys)
            xRegistry DisableClipboardRedirection {
                Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                ValueName = 'fDisableClipboardRedirection'
                ValueData = 1
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry DisableDriveRedirection {
                Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                ValueName = 'fDisableCdm'
                ValueData = 1
                ValueType = 'Dword'
                Ensure    = 'Present'
            }

            # Optimize visual effects for best performance
            xRegistry VisualFXPerformance {
                Key       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
                ValueName = 'VisualFXSetting'
                ValueData = 2
                ValueType = 'Dword'
                Ensure    = 'Present'
            }

            # Disable Windows Update (if managed externally)
            Service WindowsUpdate {
                Name        = 'wuauserv'
                StartupType = 'Disabled'
                State       = 'Stopped'
            }

            # Require Network Level Authentication (NLA)
            xRegistry RequireNLA {
                Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                ValueName = 'UserAuthentication'
                ValueData = 1
                ValueType = 'Dword'
                Ensure    = 'Present'
            }

                # Limit number of simultaneous remote connections
                xRegistry MaxConnections {
                    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
                    ValueName = 'MaxInstanceCount'
                    ValueData = 50  # Set to desired max connections
                    ValueType = 'Dword'
                    Ensure    = 'Present'
                }

                # Set encryption and security layer for RDP (SSL)
                xRegistry SecurityLayer {
                    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                    ValueName = 'SecurityLayer'
                    ValueData = 2  # 0 = RDP, 1 = Negotiate, 2 = SSL
                    ValueType = 'Dword'
                    Ensure    = 'Present'
                }

                # Configure session shadowing permissions (no remote control)
                xRegistry Shadow {
                    Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
                    ValueName = 'Shadow'
                    ValueData = 2  # 2 = No remote control, 3 = Allow
                    ValueType = 'Dword'
                    Ensure    = 'Present'
                }

                # Set logon message/banner
                xRegistry LogonMessageTitle {
                    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    ValueName = 'LegalNoticeCaption'
                    ValueData = 'WARNING'
                    ValueType = 'String'
                    Ensure    = 'Present'
                }
                xRegistry LogonMessageText {
                    Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    ValueName = 'LegalNoticeText'
                    ValueData = 'This system is for authorized use only.'
                    ValueType = 'String'
                    Ensure    = 'Present'
                }

                # Enable time zone redirection
                xRegistry TimeZoneRedirection {
                    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fEnableTimeZoneRedirection'
                    ValueData = 1
                    ValueType = 'Dword'
                    Ensure    = 'Present'
                }

                # Disable printer redirection
                xRegistry DisablePrinterRedirection {
                    Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                    ValueName = 'fDisablePrinterRedirection'
                    ValueData = 1
                    ValueType = 'Dword'
                    Ensure    = 'Present'
                }
            # User session performance improvements
            xRegistry MenuShowDelay {
                Key       = 'HKCU:\Control Panel\Desktop'
                ValueName = 'MenuShowDelay'
                ValueData = 0
                ValueType = 'String'
                Ensure    = 'Present'
            }
            xRegistry FontSmoothing {
                Key       = 'HKCU:\Control Panel\Desktop'
                ValueName = 'FontSmoothing'
                ValueData = 2
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry DisableAnimations {
                Key       = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
                ValueName = 'TaskbarAnimations'
                ValueData = 0
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry DisableCursorShadow {
                Key       = 'HKCU:\Control Panel\Desktop'
                ValueName = 'CursorShadow'
                ValueData = 0
                ValueType = 'Dword'
                Ensure    = 'Present'
            }

            # SMB performance improvements
            xRegistry SMBMultichannel {
                Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                ValueName = 'EnableMultiChannel'
                ValueData = 1
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry SMBSigning {
                Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                ValueName = 'RequireSecuritySignature'
                ValueData = 0
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry SMBLargeMTU {
                Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                ValueName = 'EnableLargeMtu'
                ValueData = 1
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry SMBCache {
                Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                ValueName = 'FileNotFoundCacheEntriesMax'
                ValueData = 1024
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
            xRegistry SMBDirectoryCache {
                Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
                ValueName = 'DirectoryCacheEntriesMax'
                ValueData = 4096
                ValueType = 'Dword'
                Ensure    = 'Present'
            }
    }
}

# To apply, run:
# RDS_Optimization_W2K19 -OutputPath C:\DSC\RDS_Optimization_W2K19
# Start-DscConfiguration -Path C:\DSC\RDS_Optimization_W2K19 -Wait -Verbose
