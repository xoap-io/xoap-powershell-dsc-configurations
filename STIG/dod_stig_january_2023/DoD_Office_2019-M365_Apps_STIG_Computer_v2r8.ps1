
Configuration 'DoD_Office_2019-M365_Apps_STIG_Computer_v2r8'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'DoD_Office_2019-M365_Apps_STIG_Computer_v2r8'
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
         {
              ValueName = 'groove.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
         {
              ValueName = 'excel.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
         {
              ValueName = 'mspub.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
         {
              ValueName = 'powerpnt.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
         {
              ValueName = 'pptview.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
         {
              ValueName = 'visio.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
         {
              ValueName = 'winproj.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
         {
              ValueName = 'winword.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
         {
              ValueName = 'outlook.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
         {
              ValueName = 'spdesign.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
         {
              ValueName = 'exprwd.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
         {
              ValueName = 'msaccess.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
         {
              ValueName = 'onenote.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
         {
              ValueName = 'mse7.exe'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\Comment'
         {
              ValueName = 'Comment'
              ValueData = 'Block all Flash activation'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
         {
              ValueName = 'enablesiphighsecuritymode'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
         {
              ValueName = 'disablehttpconnect'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              ValueName = 'ActivationFilterOverride'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              ValueName = 'Compatibility Flags'
              ValueData = 1024
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
