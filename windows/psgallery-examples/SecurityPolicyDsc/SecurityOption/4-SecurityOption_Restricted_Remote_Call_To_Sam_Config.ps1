<#PSScriptInfo
.VERSION 1.0.1
.GUID b65a2743-d89e-4a06-8cb1-a4650f7435e7
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
        This configuration will manage two network access security options using the
        MSFT_RestrictedRemoteSamSecurityDescriptor class to specify the permission
        and identity for each option.
#>
configuration SecurityOption_Restricted_Remote_Call_To_Sam_Config"
{
    Import-DscResource -ModuleName SecurityPolicyDsc

    node localhost
    {
        SecurityOption RemoteSam
        {
            Name                                                                = 'test'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(
                MSFT_RestrictedRemoteSamSecurityDescriptor
                {
                    Permission = 'Deny'
                    Identity   = 'ServerAdmin'
                }
                MSFT_RestrictedRemoteSamSecurityDescriptor
                {
                    Permission = 'Allow'
                    Identity   = 'Administrators'
                }
            )
            Network_access_Allow_anonymous_SID_Name_translation                 = 'Disabled'
        }
    }
}
