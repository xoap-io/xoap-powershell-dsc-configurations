<#
    This example will set the System Locale of LocalHost to 'ja-JP'.
    To use this example, run it using PowerShell.
#>
Configuration Example
{
    param
    (
        [Parameter()]
        [System.String[]]
        $NodeName = 'localhost'
    )

   Import-DSCResource -ModuleName SystemLocaleDsc

   Node $NodeName
   {
        SystemLocale SystemLocaleExample
        {
            IsSingleInstance = 'Yes'
            SystemLocale     = 'ja-JP'
        }
   }
}
