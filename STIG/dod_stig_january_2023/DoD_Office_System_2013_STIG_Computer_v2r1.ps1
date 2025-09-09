
Configuration 'DoD_Office_System_2013_STIG_Computer_v2r1'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_Office_System_2013_STIG_Computer_v2r1'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\enableautomaticupdates'
         {
              ValueName = 'enableautomaticupdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\common\officeupdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\hideenabledisableupdates'
         {
              ValueName = 'hideenabledisableupdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\15.0\common\officeupdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
