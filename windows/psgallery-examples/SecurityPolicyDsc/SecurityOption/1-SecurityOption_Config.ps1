<#PSScriptInfo
.VERSION 1.0.1
.GUID 612f8167-e044-4da1-b85e-0893980809e6
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/SecurityPolicyDsc/blob/master/LICENSE
.PROJECTURI https://github.com/dsccommunity/SecurityPolicyDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
Updated author, copyright notice, and URLs.
.PRIVATEDATA
#>

#Requires -Module SecurityPolicyDsc

<#
    .DESCRIPTION
        This configuration will manage a selection of account security options.
#>
configuration SecurityOption_Config"
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityOption AccountSecurityOptions
        {
            Name                                                           = 'AccountSecurityOptions'
            Accounts_Guest_account_status                                  = 'Enabled'
            Accounts_Rename_guest_account                                  = 'NewGuest'
            Accounts_Block_Microsoft_accounts                              = 'This policy is disabled'
            Network_access_Remotely_accessible_registry_paths_and_subpaths = (
                'Software\Microsoft\Windows NT\CurrentVersion\Print,' +
                'Software\Microsoft\Windows NT\CurrentVersion\Windows,' +
                'System\CurrentControlSet\Control\Print\Printers,' +
                'System\CurrentControlSet\Services\Eventlog,' +
                'Software\Microsoft\OLAP Server,' +
                'System\CurrentControlSet\Control\ContentIndex,' +
                'System\CurrentControlSet\Control\Terminal Server,' +
                'System\CurrentControlSet\Control\Terminal Server\UserConfig,' +
                'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,' +
                'Software\Microsoft\Windows NT\CurrentVersion\Perflib,' +
                'System\CurrentControlSet\Services\SysmonLog'
            )
        }
    }
}
