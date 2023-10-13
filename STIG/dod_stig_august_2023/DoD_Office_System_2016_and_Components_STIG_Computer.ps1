Configuration 'DoD_Office_System_2016_and_Components_STIG_Computer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
	
     Node 'DoD_Office_System_2016_and_Components_STIG_Computer'
	{
         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\defaultformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 51
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'defaultformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\extractdatadisableui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'extractdatadisableui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions\fglobalsheet_37_1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\options\binaryoptions'
              ValueType = 'Dword'
              ValueName = 'fglobalsheet_37_1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'excelbypassencryptedmacroscan'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\accessvbom'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'accessvbom'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'webservicefunctionwarnings'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
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
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl95workbooks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
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

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'htmlandxmlssfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock\dbasefiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'dbasefiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'openinprotectedview'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview\disableintranetcheck'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableintranetcheck'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = '1111-2222-3333-4444'
              Key = 'Software\Policies\Microsoft\OneDrive\AllowTenantList'
              ValueType = 'String'
              ValueName = '1111-2222-3333-4444'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\meetings\profile\serverui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\meetings\profile'
              ValueType = 'Dword'
              ValueName = 'serverui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\disallowattachmentcustomization'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook'
              ValueType = 'Dword'
              ValueName = 'disallowattachmentcustomization'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\autoformat\pgrfafo_25_1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\autoformat'
              ValueType = 'Dword'
              ValueName = 'pgrfafo_25_1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\blockextcontent'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'blockextcontent'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblockspecificsenders'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'unblockspecificsenders'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\unblocksafezone'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'unblocksafezone'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\trustedzone'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'trustedzone'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\internet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'internet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\intranet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'intranet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\junkmailenablelinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'junkmailenablelinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\readasplain'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'readasplain'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\readsignedasplain'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'readsignedasplain'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\editorpreference'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 65536
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'editorpreference'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail\message rtf format'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'message rtf format'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disableofficeonline'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'disableofficeonline'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\disabledav'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'disabledav'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\publishcalendardetailspolicy'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16384
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'publishcalendardetailspolicy'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal\restrictedaccessonly'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'restrictedaccessonly'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enablefulltexthtml'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
              ValueType = 'Dword'
              ValueName = 'enablefulltexthtml'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss\enableattachments'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\rss'
              ValueType = 'Dword'
              ValueName = 'enableattachments'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\enableattachments'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
              ValueType = 'Dword'
              ValueName = 'enableattachments'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal\disable'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\options\webcal'
              ValueType = 'Dword'
              ValueName = 'disable'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\rpc\enablerpcencryption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\rpc'
              ValueType = 'Dword'
              ValueName = 'enablerpcencryption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\sharedfolderscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'sharedfolderscript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\publicfolderscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'publicfolderscript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\allowactivexoneoffforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'allowactivexoneoffforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\addintrust'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'addintrust'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\enablerememberpwd'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'enablerememberpwd'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\adminsecuritymode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'adminsecuritymode'
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

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsend'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomsend'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressbookaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomaddressbookaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoommeetingtaskrequestresponse'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomsaveas'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomsaveas'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomformulaaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomformulaaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\externalsmime'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'externalsmime'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\promptoomaddressinformationaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomaddressinformationaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\msgformats'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'msgformats'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\fipsmode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'fipsmode'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\clearsign'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'clearsign'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\respondtoreceiptrequests'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'respondtoreceiptrequests'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\usecrlchasing'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'usecrlchasing'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\level'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'level'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\authenticationservice'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'authenticationservice'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\forcedefaultprofile'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'forcedefaultprofile'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\minenckey'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 168
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'minenckey'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\nocheckonsessionsecurity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'nocheckonsessionsecurity'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\outlook\security\supressnamechecks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'supressnamechecks'
         }#>

         <#RegistryPolicyFile 'DELVALS_CU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Exclusive = $True
              Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security\trustedaddins'
              Ensure = 'Present'
              ValueType = 'String'
              ValueName = ''
         }#>

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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
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
              ValueData = 0
              Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Policies\Microsoft\OneDrive\DisablePersonalSync'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
              ValueType = 'Dword'
              ValueName = 'DisablePersonalSync'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\trustwss'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'trustwss'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\ms project\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = '1111-2222-3333-4444'
              Key = 'Software\Policies\Microsoft\OneDrive\AllowTenantList'
              ValueType = 'String'
              ValueName = '1111-2222-3333-4444'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\visio\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         RegistryPolicyFile 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\keycupoliciesmsvbasecurity'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'loadcontrolsinforms'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\sendcustomerdata'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common'
              ValueType = 'Dword'
              ValueName = 'sendcustomerdata'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disabledefaultservice'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
              ValueType = 'Dword'
              ValueName = 'disabledefaultservice'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\broadcast\disableprogrammaticaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\broadcast'
              ValueType = 'Dword'
              ValueName = 'disableprogrammaticaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\drm\requireconnection'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\drm'
              ValueType = 'Dword'
              ValueName = 'requireconnection'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\feedback\includescreenshot'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\feedback'
              ValueType = 'Dword'
              ValueName = 'includescreenshot'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\fixedformat\disablefixedformatdocproperties'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\fixedformat'
              ValueType = 'Dword'
              ValueName = 'disablefixedformatdocproperties'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\ptwatson\ptwoptin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\ptwatson'
              ValueType = 'Dword'
              ValueName = 'ptwoptin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\drmencryptproperty'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'Dword'
              ValueName = 'drmencryptproperty'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryptproperty'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'Dword'
              ValueName = 'openxmlencryptproperty'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\openxmlencryption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'String'
              ValueName = 'openxmlencryption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\defaultencryption12'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'String'
              ValueName = 'defaultencryption12'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\encryptdocprops'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security'
              ValueType = 'Dword'
              ValueName = 'encryptdocprops'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations\allow user locations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allow user locations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\trustcenter\trustbar'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\trustcenter'
              ValueType = 'Dword'
              ValueName = 'trustbar'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\osm\enablefileobfuscation'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\osm'
              ValueType = 'Dword'
              ValueName = 'enablefileobfuscation'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs\requireserververification'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\wef\trustedcatalogs'
              ValueType = 'Dword'
              ValueName = 'requireserververification'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'uficontrols'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecurity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueType = 'Dword'
              ValueName = 'automationsecurity'
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

         <#RegistryPolicyFile 'Registry(POL): HKCU:\SOFTWARE\Policies\Microsoft\OneDrive\DisablePersonalSync'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
              ValueType = 'Dword'
              ValueName = 'DisablePersonalSync'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\promptforbadfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher'
              ValueType = 'Dword'
              ValueName = 'promptforbadfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\publisher\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
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
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueType = 'Dword'
              ValueName = 'automationsecuritypublisher'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\internet\donotunderlinehyperlinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\internet'
              ValueType = 'Dword'
              ValueName = 'donotunderlinehyperlinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\modaltrustdecisiononly'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'modaltrustdecisiononly'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\access\settings\default file format'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 12
              Key = 'HKCU:\software\policies\microsoft\office\16.0\access\settings'
              ValueType = 'Dword'
              ValueName = 'default file format'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\policies\microsoft\office\16.0\lync'
              ValueType = 'Dword'
              ValueName = 'savepassword'
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

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\common\research\translation\useonline'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\common\research\translation'
              ValueType = 'Dword'
              ValueName = 'useonline'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\defaultformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = '
'
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
              ValueType = 'String'
              ValueName = 'defaultformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\options\dontupdatelinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\options'
              ValueType = 'Dword'
              ValueName = 'dontupdatelinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'wordbypassencryptedmacroscan'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\accessvbom'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'accessvbom'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
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
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2000files'
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
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word95files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\word97files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word97files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock\wordxpfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'wordxpfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'openinprotectedview'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview\disableintranetcheck'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableintranetcheck'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\options\defaultformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 27
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\options'
              ValueType = 'Dword'
              ValueName = 'defaultformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'powerpointbypassencryptedmacroscan'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\accessvbom'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'accessvbom'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'runprograms'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
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

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'openinprotectedview'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview\disableintranetcheck'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableintranetcheck'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
