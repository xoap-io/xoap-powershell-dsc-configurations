function Get-DscConfigurationVersion
{
    $key = Get-Item HKLM:\SOFTWARE\DscTagging
    $hash = @{ }
    foreach ($property in $key.Property)
    {
        $hash.Add($property, $key.GetValue($property))
    }

    New-Object -TypeName PSObject -Property $hash
}

function Get-DscLcmControllerSettings
{
    $key = Get-Item HKLM:\SOFTWARE\DscLcmController
    $hash = @{ }
    foreach ($property in $key.Property)
    {
        $hash.Add($property, $key.GetValue($property))
    }

    $maintenanceWindows = Get-ChildItem -Path HKLM:\SOFTWARE\DscLcmController\MaintenanceWindows
    $maintenanceWindowsHash = @{ }
    foreach ($maintenanceWindow in $maintenanceWindows)
    {
        $mwHash = @{ }
        foreach ($property in $maintenanceWindow.Property)
        {
            $mwHash.Add($property, $maintenanceWindow.GetValue($property))
        }
        $maintenanceWindowsHash.Add($maintenanceWindow.PSChildName, $mwHash)
    }

    $hash.Add('MaintenanceWindows', (New-Object -TypeName PSObject -Property $maintenanceWindowsHash))

    New-Object -TypeName PSObject -Property $hash
}

function Test-DscConfiguration
{
    PSDesiredStateConfiguration\Test-DscConfiguration -Detailed -Verbose
}
function Update-DscConfiguration
{
    PSDesiredStateConfiguration\Update-DscConfiguration -Wait -Verbose
}

function Get-DscLocalConfigurationManager
{
    PSDesiredStateConfiguration\Get-DscLocalConfigurationManager
}
function Get-DscLcmControllerLog
{
    param (
        [Parameter()]
        [switch]$AutoCorrect,

        [Parameter()]
        [switch]$Refresh,

        [Parameter()]
        [switch]$Monitor,

        [Parameter()]
        [int]$Last = 1000
    )


    Import-Csv -Path C:\ProgramData\Dsc\LcmController\LcmControllerSummary.txt | Where-Object {
        if ($AutoCorrect)
        {
            [bool][int]$_.DoAutoCorrect -eq $AutoCorrect
        }
        else
        {
            $true
        }
    } | Where-Object {
        if ($Refresh)
        {
            [bool][int]$_.DoRefresh -eq $Refresh
        }
        else
        {
            $true
        }
    } | Where-Object {
        if ($Monitor)
        {
            [bool][int]$_.DoMonitor -eq $Monitor
        }
        else
        {
            $true
        }
    } | Microsoft.PowerShell.Utility\Select-Object -Last $Last
}

function Start-DscConfiguration
{
    PSDesiredStateConfiguration\Start-DscConfiguration -UseExisting -Wait -Verbose
}

function Get-DscOperationalEventLog
{
    Get-WinEvent -LogName 'Microsoft-Windows-Dsc/Operational'
}
function Get-DscTraceInformation
{
    param (
        [Parameter()]
        [int]$Last = 100
    )

    if (-not (Get-Module -ListAvailable -Name xDscDiagnostics))
    {
        Write-Error 'This function required the module 'xDscDiagnostics' to be present on the system'
        return
    }

    $failedJobs = Get-xDscOperation -Newest $Last | Where-Object Result -eq 'Failure'

    foreach ($failedJob in $failedJobs)
    {
        if ($failedJob.JobID)
        {
            Trace-xDscOperation -JobId $failedJob.JobID
        }
        else
        {
            Trace-xDscOperation -SequenceID $failedJob.SequenceId
        }
    }
}

#-------------------------------------------------------------------------------------------

Configuration DscDiagnostic {

    Import-DscResource -ModuleName JeaDsc

    $visibleFunctions = 'Test-DscConfiguration',
    'Get-DscConfigurationVersion',
    'Update-DscConfiguration',
    'Get-DscLcmControllerLog',
    'Start-DscConfiguration',
    'Get-DscOperationalEventLog',
    'Get-DscTraceInformation',
    'Get-DscLcmControllerSettings',
    'Get-DscLocalConfigurationManager'

    $functionDefinitions = @()
    foreach ($visibleFunction in $visibleFunctions)
    {
        $functionDefinitions += @{
            Name        = $visibleFunction
            ScriptBlock = (Get-Command -Name $visibleFunction).ScriptBlock
        } | ConvertTo-Expression
    }

    JeaRoleCapabilities ReadDiagnosticRole
    {
        Path                = 'C:\Program Files\WindowsPowerShell\Modules\DscDiagnostics\RoleCapabilities\ReadDiagnosticsRole.psrc'
        VisibleFunctions    = $visibleFunctions
        FunctionDefinitions = $functionDefinitions
    }

    JeaSessionConfiguration DscEndpoint
    {
        Ensure          = 'Present'
        DependsOn       = '[JeaRoleCapabilities]ReadDiagnosticRole'
        Name            = 'DSC'
        RoleDefinitions = '@{ Everyone = @{ RoleCapabilities = 'ReadDiagnosticsRole' } }'
        SessionType     = 'RestrictedRemoteServer'
        ModulesToImport = 'PSDesiredStateConfiguration', 'xDscDiagnostics'
    }
}

Get-PSSession | Remove-PSSession
Remove-Item -Path C:\DscTest\* -ErrorAction SilentlyContinue
DscDiagnostic -OutputPath C:\DscTest -Verbose

PSDesiredStateConfiguration\Start-DscConfiguration -Path C:\DscTest -Wait -Verbose -Force

$s = New-PSSession -ComputerName localhost -ConfigurationName DSC
Import-PSSession -Session $s -Prefix x

<#
The follwoing cmdlets will be available after importing the session
Get-xDscConfigurationVersion
Update-xDscConfiguration
Get-xDscLcmControllerLog
Get-DscLcmControllerSettings
Get-DscOperationalEventLog
Get-DscTraceInformation
#>
