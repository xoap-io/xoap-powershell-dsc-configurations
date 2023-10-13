Configuration 'DoD_Office_System_2013_and_Components_STIG_Computer'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'
	
     Node 'DoD_Office_System_2013_and_Components_STIG_Computer'
	{
         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\research\translation\useonline'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\research\translation'
              ValueType = 'Dword'
              ValueName = 'useonline'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\defaultformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = '
'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueType = 'String'
              ValueName = 'defaultformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\dontupdatelinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueType = 'Dword'
              ValueName = 'dontupdatelinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\warnrevisions'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueType = 'Dword'
              ValueName = 'warnrevisions'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\options\custommarkupwarning'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\options'
              ValueType = 'Dword'
              ValueName = 'custommarkupwarning'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\wordbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueType = 'Dword'
              ValueName = 'wordbypassencryptedmacroscan'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\accessvbom'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueType = 'Dword'
              ValueName = 'accessvbom'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word2files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word2000files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word2000files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word60files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word60files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word95files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word95files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\word97files'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'word97files'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock\wordxpfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'wordxpfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview\disableinternetfilesinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableinternetfilesinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview\disableunsafelocationsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableunsafelocationsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\word\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\disableinfopath2003emailforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath'
              ValueType = 'Dword'
              ValueName = 'disableinfopath2003emailforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\deployment\cachemailxsn'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\deployment'
              ValueType = 'Dword'
              ValueName = 'cachemailxsn'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\deployment\mailxsnwithxml'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\deployment'
              ValueType = 'Dword'
              ValueName = 'mailxsnwithxml'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\editor\offline\cachedmodestatus'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\editor\offline'
              ValueType = 'Dword'
              ValueName = 'cachedmodestatus'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\gradualupgraderedirection'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'gradualupgraderedirection'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\emailformsruncodeandscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'emailformsruncodeandscript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\emailformsbeaconingui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'emailformsbeaconingui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enablefulltrustemailforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'enablefulltrustemailforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enableinternetemailforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'enableinternetemailforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enablerestrictedemailforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'enablerestrictedemailforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\runfulltrustsolutions'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'runfulltrustsolutions'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\allowinternetsolutions'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'allowinternetsolutions'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\infopathbeaconingui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'infopathbeaconingui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\editoractivexbeaconingui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'editoractivexbeaconingui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\disallowattachmentcustomization'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'disallowattachmentcustomization'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\enableintranetemailforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'enableintranetemailforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\runmanagedcodefrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'runmanagedcodefrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\signaturewarning'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'signaturewarning'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\infopath\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\infopath\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\disableinfopathforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'disableinfopathforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\visio\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\visio\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\visio\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\visio\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\ms project\security\trustwss'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\ms project\security'
              ValueType = 'Dword'
              ValueName = 'trustwss'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\promptforbadfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher'
              ValueType = 'Dword'
              ValueName = 'promptforbadfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\publisher\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\publisher\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\security\automationsecuritypublisher'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\common\security'
              ValueType = 'Dword'
              ValueName = 'automationsecuritypublisher'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\infopath\security\aptca_allowlist'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\15.0\infopath\security'
              ValueType = 'Dword'
              ValueName = 'aptca_allowlist'
         }

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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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
              ValueData = 1
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

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\enableautomaticupdates'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\15.0\common\officeupdate'
              ValueType = 'Dword'
              ValueName = 'enableautomaticupdates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\hideenabledisableupdates'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\15.0\common\officeupdate'
              ValueType = 'Dword'
              ValueName = 'hideenabledisableupdates'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'groove.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'excel.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'mspub.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'powerpnt.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'pptview.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'visio.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'winproj.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'winword.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'outlook.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'spdesign.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'exprwd.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'msaccess.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'onenote.exe'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
              ValueType = 'Dword'
              ValueName = 'mse7.exe'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\internet\donotloadpictures'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\internet'
              ValueType = 'Dword'
              ValueName = 'donotloadpictures'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\defaultformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 51
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'defaultformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\autohyperlink'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'autohyperlink'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\disableautorepublish'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'disableautorepublish'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\disableautorepublishwarning'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'disableautorepublishwarning'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\extractdatadisableui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options'
              ValueType = 'Dword'
              ValueName = 'extractdatadisableui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions\fupdateext_78_1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions'
              ValueType = 'Dword'
              ValueName = 'fupdateext_78_1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions\fglobalsheet_37_1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\options\binaryoptions'
              ValueType = 'Dword'
              ValueName = 'fglobalsheet_37_1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\excelbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'excelbypassencryptedmacroscan'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\accessvbom'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'accessvbom'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\extensionhardening'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'extensionhardening'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\webservicefunctionwarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'webservicefunctionwarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\excel12betafilesfromconverters'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'excel12betafilesfromconverters'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\dbasefiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'dbasefiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\difandsylkfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'difandsylkfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl2macros'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl2macros'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl2worksheets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl2worksheets'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl3macros'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl3macros'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl3worksheets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl3worksheets'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl4macros'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl4macros'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl4workbooks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl4workbooks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl4worksheets'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl4worksheets'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl95workbooks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl95workbooks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\xl9597workbooksandtemplates'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 5
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'xl9597workbooksandtemplates'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock\htmlandxmlssfiles'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'htmlandxmlssfiles'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview\disableinternetfilesinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableinternetfilesinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview\disableunsafelocationsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableunsafelocationsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\excel\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\savepassword'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'software\policies\microsoft\office\15.0\lync'
              ValueType = 'Dword'
              ValueName = 'savepassword'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\enablesiphighsecuritymode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\15.0\lync'
              ValueType = 'Dword'
              ValueName = 'enablesiphighsecuritymode'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\disablehttpconnect'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'software\policies\microsoft\office\15.0\lync'
              ValueType = 'Dword'
              ValueName = 'disablehttpconnect'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\internet\donotunderlinehyperlinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\internet'
              ValueType = 'Dword'
              ValueName = 'donotunderlinehyperlinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\modaltrustdecisiononly'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueType = 'Dword'
              ValueName = 'modaltrustdecisiononly'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\settings\default file format'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 12
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\settings'
              ValueType = 'Dword'
              ValueName = 'default file format'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\access\settings\noconvertdialog'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\access\settings'
              ValueType = 'Dword'
              ValueName = 'noconvertdialog'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\mailsettings\disablesignatures'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\mailsettings'
              ValueType = 'Dword'
              ValueName = 'disablesignatures'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\mailsettings\plainwraplen'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 132
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\mailsettings'
              ValueType = 'Dword'
              ValueName = 'plainwraplen'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\meetings\profile\serverui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\meetings\profile'
              ValueType = 'Dword'
              ValueName = 'serverui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\disableantispam'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook'
              ValueType = 'Dword'
              ValueName = 'disableantispam'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\disallowattachmentcustomization'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook'
              ValueType = 'Dword'
              ValueName = 'disallowattachmentcustomization'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\autoformat\pgrfafo_25_1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\autoformat'
              ValueType = 'Dword'
              ValueName = 'pgrfafo_25_1'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\calendar\disableweather'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\calendar'
              ValueType = 'Dword'
              ValueName = 'disableweather'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\general\check default client'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\general'
              ValueType = 'Dword'
              ValueName = 'check default client'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\general\msgformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\general'
              ValueType = 'Dword'
              ValueName = 'msgformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\unblocksafezone'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'unblocksafezone'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\junkmailtrustoutgoingrecipients'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'junkmailtrustoutgoingrecipients'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\trustedzone'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'trustedzone'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\junkmailenablelinks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'junkmailenablelinks'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\internet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'internet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\intranet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'intranet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\blockextcontent'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'blockextcontent'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\unblockspecificsenders'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'unblockspecificsenders'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\message plain format mime'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'message plain format mime'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\readasplain'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'readasplain'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\readsignedasplain'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'readsignedasplain'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\junkmailtrustcontacts'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'junkmailtrustcontacts'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\message rtf format'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'message rtf format'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail\editorpreference'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 65536
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\mail'
              ValueType = 'Dword'
              ValueName = 'editorpreference'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\restrictedaccessonly'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'restrictedaccessonly'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\disabledav'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'disabledav'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\disableofficeonline'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'disableofficeonline'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\publishcalendardetailspolicy'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 16384
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'publishcalendardetailspolicy'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal\singleuploadonly'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\pubcal'
              ValueType = 'Dword'
              ValueName = 'singleuploadonly'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\enablefulltexthtml'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueType = 'Dword'
              ValueName = 'enablefulltexthtml'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\synctosyscfl'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueType = 'Dword'
              ValueName = 'synctosyscfl'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\disable'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueType = 'Dword'
              ValueName = 'disable'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss\enableattachments'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\rss'
              ValueType = 'Dword'
              ValueName = 'enableattachments'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal\disable'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal'
              ValueType = 'Dword'
              ValueName = 'disable'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal\enableattachments'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\options\webcal'
              ValueType = 'Dword'
              ValueName = 'enableattachments'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\rpc\enablerpcencryption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\rpc'
              ValueType = 'Dword'
              ValueName = 'enablerpcencryption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\allowactivexoneoffforms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'allowactivexoneoffforms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\enableoneoffformscripts'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'enableoneoffformscripts'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\addintrust'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'addintrust'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomaddressbookaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomaddressbookaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\allowuserstolowerattachments'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'allowuserstolowerattachments'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomformulaaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomformulaaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomsaveas'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomsaveas'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomaddressinformationaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomaddressinformationaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoommeetingtaskrequestresponse'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoommeetingtaskrequestresponse'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomsend'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomsend'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\enablerememberpwd'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'enablerememberpwd'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\dontpromptlevel1attachclose'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'dontpromptlevel1attachclose'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\dontpromptlevel1attachsend'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'dontpromptlevel1attachsend'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\showlevel1attach'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'showlevel1attach'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\nondefaultstorescript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'nondefaultstorescript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\publicfolderscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'publicfolderscript'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\sharedfolderscript'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'sharedfolderscript'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\outlooksecuretempfolder'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'outlooksecuretempfolder'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\authenticationservice'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 9
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'authenticationservice'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\msgformats'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'msgformats'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\sigstatusnotrustdecision'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'sigstatusnotrustdecision'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\adminsecuritymode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 3
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'adminsecuritymode'
         }#>

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel1'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'fileextensionsremovelevel1'
         }

         RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel2'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              Ensure = 'Absent'
              ValueType = 'String'
              ValueName = 'fileextensionsremovelevel2'
         }

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\usecrlchasing'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'usecrlchasing'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\fipsmode'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'fipsmode'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\externalsmime'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'externalsmime'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\respondtoreceiptrequests'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'respondtoreceiptrequests'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\level'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'level'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\clearsign'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'clearsign'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\promptoomcustomaction'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'promptoomcustomaction'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\warnaboutinvalid'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'warnaboutinvalid'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\forcedefaultprofile'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'forcedefaultprofile'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\minenckey'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 168
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'minenckey'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\nocheckonsessionsecurity'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'nocheckonsessionsecurity'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\outlook\security\supressnamechecks'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
              ValueType = 'Dword'
              ValueName = 'supressnamechecks'
         }#>

         <#RegistryPolicyFile 'DELVALS_CU:\software\policies\microsoft\office\15.0\outlook\security\trustedaddins'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = ''
              Exclusive = $True
              Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security\trustedaddins'
              Ensure = 'Present'
              ValueType = 'String'
              ValueName = ''
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\options\defaultformat'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 27
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\options'
              ValueType = 'Dword'
              ValueName = 'defaultformat'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\options\markupopensave'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\options'
              ValueType = 'Dword'
              ValueName = 'markupopensave'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\notbpromptunsignedaddin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'notbpromptunsignedaddin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\powerpointbypassencryptedmacroscan'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'powerpointbypassencryptedmacroscan'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\accessvbom'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'accessvbom'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\vbawarnings'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'vbawarnings'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\runprograms'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'runprograms'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\downloadimages'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'downloadimages'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\requireaddinsig'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'requireaddinsig'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\blockcontentexecutionfrominternet'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security'
              ValueType = 'Dword'
              ValueName = 'blockcontentexecutionfrominternet'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock\powerpoint12betafilesfromconverters'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\fileblock'
              ValueType = 'Dword'
              ValueName = 'powerpoint12betafilesfromconverters'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation\enableonload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'enableonload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation\openinprotectedview'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'openinprotectedview'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation\disableeditfrompv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation'
              ValueType = 'Dword'
              ValueName = 'disableeditfrompv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview\disableinternetfilesinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableinternetfilesinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview\disableunsafelocationsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableunsafelocationsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview\disableattachmentsinpv'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\protectedview'
              ValueType = 'Dword'
              ValueName = 'disableattachmentsinpv'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations\alllocationsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'alllocationsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations\allownetworklocations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allownetworklocations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\powerpoint\slide libraries\disableslideupdate'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\powerpoint\slide libraries'
              ValueType = 'Dword'
              ValueName = 'disableslideupdate'
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

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\qmenable'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common'
              ValueType = 'Dword'
              ValueName = 'qmenable'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\updatereliabilitydata'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common'
              ValueType = 'Dword'
              ValueName = 'updatereliabilitydata'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\broadcast\disabledefaultservice'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\broadcast'
              ValueType = 'Dword'
              ValueName = 'disabledefaultservice'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\broadcast\disableprogrammaticaccess'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\broadcast'
              ValueType = 'Dword'
              ValueName = 'disableprogrammaticaccess'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\documentinformationpanel\beaconing'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\documentinformationpanel'
              ValueType = 'Dword'
              ValueName = 'beaconing'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\drm\includehtml'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\drm'
              ValueType = 'Dword'
              ValueName = 'includehtml'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\drm\requireconnection'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\drm'
              ValueType = 'Dword'
              ValueName = 'requireconnection'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\drm\disablecreation'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\drm'
              ValueType = 'Dword'
              ValueName = 'disablecreation'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\feedback\includescreenshot'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\feedback'
              ValueType = 'Dword'
              ValueName = 'includescreenshot'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\feedback\enabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\feedback'
              ValueType = 'Dword'
              ValueName = 'enabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\fixedformat\disablefixedformatdocproperties'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\fixedformat'
              ValueType = 'Dword'
              ValueName = 'disablefixedformatdocproperties'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\general\shownfirstrunoptin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\general'
              ValueType = 'Dword'
              ValueName = 'shownfirstrunoptin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\general\skydrivesigninoption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\general'
              ValueType = 'Dword'
              ValueName = 'skydrivesigninoption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\internet\opendocumentsreadwritewhilebrowsing'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\internet'
              ValueType = 'Dword'
              ValueName = 'opendocumentsreadwritewhilebrowsing'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\internet\relyonvml'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\internet'
              ValueType = 'Dword'
              ValueName = 'relyonvml'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\internet\useonlinecontent'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\internet'
              ValueType = 'Dword'
              ValueName = 'useonlinecontent'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\portal\linkpublishingdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\portal'
              ValueType = 'Dword'
              ValueName = 'linkpublishingdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\ptwatson\ptwoptin'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\ptwatson'
              ValueType = 'Dword'
              ValueName = 'ptwoptin'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\roaming\roamingsettingsdisabled'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\roaming'
              ValueType = 'Dword'
              ValueName = 'roamingsettingsdisabled'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\defaultencryption12'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'String'
              ValueName = 'defaultencryption12'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\openxmlencryption'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 'Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256'
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'String'
              ValueName = 'openxmlencryption'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\disablehyperlinkwarning'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'Dword'
              ValueName = 'disablehyperlinkwarning'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\disablepasswordui'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'Dword'
              ValueName = 'disablepasswordui'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\openxmlencryptproperty'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'Dword'
              ValueName = 'openxmlencryptproperty'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\drmencryptproperty'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'Dword'
              ValueName = 'drmencryptproperty'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\encryptdocprops'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security'
              ValueType = 'Dword'
              ValueName = 'encryptdocprops'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\security\trusted locations\allow user locations'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\security\trusted locations'
              ValueType = 'Dword'
              ValueName = 'allow user locations'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\services\fax\nofax'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\services\fax'
              ValueType = 'Dword'
              ValueName = 'nofax'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\signatures\enablecreationofweakxpsignatures'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\signatures'
              ValueType = 'Dword'
              ValueName = 'enablecreationofweakxpsignatures'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\signatures\suppressextsigningsvcs'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\signatures'
              ValueType = 'Dword'
              ValueName = 'suppressextsigningsvcs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\signin\signinoptions'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 2
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\signin'
              ValueType = 'Dword'
              ValueName = 'signinoptions'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\common\trustcenter\trustbar'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\common\trustcenter'
              ValueType = 'Dword'
              ValueName = 'trustbar'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\firstrun\disablemovie'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\firstrun'
              ValueType = 'Dword'
              ValueName = 'disablemovie'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\firstrun\bootedrtm'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\firstrun'
              ValueType = 'Dword'
              ValueName = 'bootedrtm'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\gfx\disablescreenshotautohyperlink'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\gfx'
              ValueType = 'Dword'
              ValueName = 'disablescreenshotautohyperlink'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\osm\enableupload'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 0
              Key = 'HKCU:\software\policies\microsoft\office\15.0\osm'
              ValueType = 'Dword'
              ValueName = 'enableupload'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\osm\enablefileobfuscation'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\osm'
              ValueType = 'Dword'
              ValueName = 'enablefileobfuscation'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\osm\enablelogging'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\osm'
              ValueType = 'Dword'
              ValueName = 'enablelogging'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs\requireserververification'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs'
              ValueType = 'Dword'
              ValueName = 'requireserververification'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs\disableomexcatalogs'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\15.0\wef\trustedcatalogs'
              ValueType = 'Dword'
              ValueName = 'disableomexcatalogs'
         }#>

         <#RegistryPolicyFile 'Registry(POL): HKCU:\software\policies\microsoft\office\common\blog\disableblog'
         {
              TargetType = 'ComputerConfiguration'
              ValueData = 1
              Key = 'HKCU:\software\policies\microsoft\office\common\blog'
              ValueType = 'Dword'
              ValueName = 'disableblog'
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

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
