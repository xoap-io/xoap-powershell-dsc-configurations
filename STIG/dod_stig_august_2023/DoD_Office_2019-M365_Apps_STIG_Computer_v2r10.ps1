Configuration 'DoD_Office_2019-M365_Apps_STIG_Computer_v2r10'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	
     Node 'DoD_Office_2019-M365_Apps_STIG_Computer_v2r10'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\Comment'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Block all Flash activation'
              Key = 'software\microsoft\Office\Common\COM Compatibility'
              ValueType = 'String'
              ValueName = 'Comment'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\16.0\lync'
              ValueType = 'Dword'
              ValueName = 'enablesiphighsecuritymode'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\16.0\lync'
              ValueType = 'Dword'
              ValueName = 'disablehttpconnect'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'ActivationFilterOverride'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1024
              Key = 'software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
              ValueType = 'Dword'
              ValueName = 'Compatibility Flags'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\portal\linkpublishingdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\portal'
              ValueType = 'Dword'
              ValueName = 'linkpublishingdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\macroruntimescanscope'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'Dword'
              ValueName = 'macroruntimescanscope'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'Dword'
              ValueName = 'drmencryptproperty'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'String'
              ValueName = 'defaultencryption12'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'String'
              ValueName = 'openxmlencryption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allow user locations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\access'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\excel'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\infopath'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\outlook'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\powerpoint'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\project'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\publisher'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\visio'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word\noextensibilitycustomizationfromdocument'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\toolbars\word'
              ValueType = 'Dword'
              ValueName = 'noextensibilitycustomizationfromdocument'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueType = 'Dword'
              ValueName = 'trustbar'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\internet\donotloadpictures'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\internet'
              ValueType = 'Dword'
              ValueName = 'donotloadpictures'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'extractdatadisableui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublish'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'disableautorepublish'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\disableautorepublishwarning'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'disableautorepublishwarning'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fupdateext_78_1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueType = 'Dword'
              ValueName = 'fupdateext_78_1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\extensionhardening'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'extensionhardening'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'excelbypassencryptedmacroscan'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'webservicefunctionwarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlaunch'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueType = 'Dword'
              ValueName = 'disableddeserverlaunch'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\disableddeserverlookup'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueType = 'Dword'
              ValueName = 'disableddeserverlookup'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\external content\enableblockunsecurequeryfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\external content'
              ValueType = 'Dword'
              ValueName = 'enableblockunsecurequeryfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'dbasefiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\difandsylkfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'difandsylkfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2macros'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl2macros'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl2worksheets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl2worksheets'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3macros'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl3macros'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl3worksheets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl3worksheets'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4macros'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl4macros'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4workbooks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl4workbooks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl4worksheets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl4worksheets'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl95workbooks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl95workbooks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl9597workbooksandtemplates'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'htmlandxmlssfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\enabledatabasefileprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'enabledatabasefileprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableinternetfilesinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableinternetfilesinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableunsafelocationsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableunsafelocationsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueType = 'Dword'
              ValueName = 'disallowattachmentcustomization'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\general\msgformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\general'
              ValueType = 'Dword'
              ValueName = 'msgformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'internet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'junkmailenablelinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueType = 'Dword'
              ValueName = 'enablerpcencryption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'authenticationservice'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'publicfolderscript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'sharedfolderscript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'allowactivexoneoffforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publishtogaldisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'publishtogaldisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 168
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'minenckey'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\warnaboutinvalid'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'warnaboutinvalid'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'usecrlchasing'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'adminsecuritymode'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowuserstolowerattachments'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'allowuserstolowerattachments'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\showlevel1attach'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'showlevel1attach'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'fileextensionsremovelevel1'
         }

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'fileextensionsremovelevel2'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enableoneoffformscripts'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'enableoneoffformscripts'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomcustomaction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomcustomaction'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomaddressbookaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomformulaaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomsaveas'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomaddressinformationaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoommeetingtaskrequestresponse'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomsend'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'level'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'runprograms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'powerpointbypassencryptedmacroscan'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\binaryfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'binaryfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableinternetfilesinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableinternetfilesinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableunsafelocationsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2000files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'visio2000files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio2003files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'visio2003files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock\visio50andearlierfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'visio50andearlierfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'wordbypassencryptedmacroscan'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2000files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2000files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2003files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2003files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word2007files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2007files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word60files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word60files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word95files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word95files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word97files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'wordxpfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableinternetfilesinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableinternetfilesinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableunsafelocationsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableunsafelocationsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\uficontrols'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 6
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueType = 'Dword'
              ValueName = 'uficontrols'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueType = 'Dword'
              ValueName = 'automationsecurity'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueType = 'Dword'
              ValueName = 'automationsecuritypublisher'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\smart tag\neverloadmanifests'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\common\smart tag'
              ValueType = 'Dword'
              ValueName = 'neverloadmanifests'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\vba\security\loadcontrolsinforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\vba\security'
              ValueType = 'Dword'
              ValueName = 'loadcontrolsinforms'
         }#>

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
