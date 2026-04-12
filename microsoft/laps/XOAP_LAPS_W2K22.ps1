# DSC Configuration: XOAP_LAPS_W2K22
# Purpose: Configures Modern Windows LAPS (Local Administrator Password Solution) policy for Windows Server 2022.
Configuration 'XOAP_LAPS_W2K22'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node 'XOAP_LAPS_W2K22'
    {
        # --- Windows LAPS: Backup Directory ---
        # 1 = Azure Active Directory / Entra ID, 2 = Active Directory
        Registry 'LAPS_BackupDirectory'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Ensure    = 'Present'
            ValueName = 'BackupDirectory'
            ValueType = 'Dword'
            ValueData = '1'
        }

        # --- Windows LAPS: Password Age (days) ---
        Registry 'LAPS_PasswordAgeDays'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Ensure    = 'Present'
            ValueName = 'PasswordAgeDays'
            ValueType = 'Dword'
            ValueData = '30'
        }

        # --- Windows LAPS: Password Length ---
        Registry 'LAPS_PasswordLength'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Ensure    = 'Present'
            ValueName = 'PasswordLength'
            ValueType = 'Dword'
            ValueData = '14'
        }

        # --- Windows LAPS: Password Complexity (4 = upper+lower+digits+special) ---
        Registry 'LAPS_PasswordComplexity'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Ensure    = 'Present'
            ValueName = 'PasswordComplexity'
            ValueType = 'Dword'
            ValueData = '4'
        }

        # --- Windows LAPS: Post-Authentication Reset Delay (hours) ---
        Registry 'LAPS_PostAuthResetDelay'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Ensure    = 'Present'
            ValueName = 'PostAuthenticationResetDelay'
            ValueType = 'Dword'
            ValueData = '24'
        }

        # --- Windows LAPS: Post-Authentication Actions (3 = reset password + logoff) ---
        Registry 'LAPS_PostAuthActions'
        {
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            Ensure    = 'Present'
            ValueName = 'PostAuthenticationActions'
            ValueType = 'Dword'
            ValueData = '3'
        }
    }
}
XOAP_LAPS_W2K22 -OutputPath 'C:\DSC\XOAP_LAPS_W2K22'
