
Configuration 'MSTF_SecurityBaseline_W2K25_2506_IE11_User'
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node 'MSTF_SecurityBaseline_W2K25_2506_IE11_User'
	{
         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel\FormSuggest Passwords'
         {
              ValueName = 'FormSuggest Passwords'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FormSuggest PW Ask'
         {
              ValueName = 'FormSuggest PW Ask'
              ValueData = 'no'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\Software\Policies\Microsoft\Internet Explorer\Main\FormSuggest Passwords'
         {
              ValueName = 'FormSuggest Passwords'
              ValueData = 'no'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKCU:\Software\Policies\Microsoft\Internet Explorer\Main'
         }#>

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
MSTF_SecurityBaseline_W2K25_2506_IE11_User -OutputPath 'C:\DSC\MSTF_SecurityBaseline_W2K25_2506_IE11_User'
