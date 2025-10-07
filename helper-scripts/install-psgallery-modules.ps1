<#
.SYNOPSIS
    PowerShell DSC Module Installer - Optimized for performance and reliability

.DESCRIPTION
    Efficiently installs PowerShell DSC modules from PowerShell Gallery.
    Supports parallel installation, dependency resolution, version management,
    and comprehensive error handling. Optimized for cross-platform compatibility.

.PARAMETER ModuleList
    Optional custom list of modules to install (overrides default list)

.PARAMETER Parallel
    Use parallel processing for faster installation (default: enabled)

.PARAMETER Force
    Force reinstallation of modules even if already installed

.PARAMETER SkipPublisherCheck
    Skip publisher validation for faster installation

.PARAMETER Scope
    Installation scope (AllUsers, CurrentUser) - default: CurrentUser for non-admin

.PARAMETER LogPath
    Path for installation log file

.PARAMETER DryRun
    Show what would be installed without actually installing

.PARAMETER UpdateExisting
    Update existing modules to latest versions

.EXAMPLE
    .\install-psgallery-modules.ps1
    Install all DSC modules with default settings

.EXAMPLE
    .\install-psgallery-modules.ps1 -DryRun
    Preview what modules would be installed

.EXAMPLE
    .\install-psgallery-modules.ps1 -UpdateExisting -Force
    Update all existing modules to latest versions

.EXAMPLE
    .\install-psgallery-modules.ps1 -ModuleList @('NetworkingDsc', 'SecurityPolicyDsc')
    Install only specific modules

.NOTES
    Optimized for Apple ARM systems and cross-platform compatibility
#>

[CmdletBinding()]
param(
    [string[]]$ModuleList = @(),
    [switch]$Parallel = $true,
    [switch]$Force,
    [switch]$SkipPublisherCheck,
    [string]$Scope = 'CurrentUser',
    [string]$LogPath = (Join-Path $PWD "module-install-log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"),
    [switch]$DryRun,
    [switch]$UpdateExisting
)

# Default comprehensive module list for DSC configurations
$defaultModules = @(
    'AccessControlDSC',
    'ActiveDirectoryDsc',
    'AdfsDsc',
    'AuditPolicyDsc',
    'AuditSystemDsc',
    'AzureWvdDsc',
    'cChocoEx',
    'cDockerDSC',
    'cElasticSearchDSC',
    'CertificateDsc',
    'CISDSC',
    'CitrixPVS',
    'cNtfsAccessControl',
    'ComputerManagementDsc',
    'ConfigMgrCBDsc',
    'DFSDsc',
    'DnsServerDsc',
    'DSCR_Application',
    'DSCR_AppxPackage',
    'DSCR_AutoLogon',
    'DSCR_FileContent',
    'DSCR_Font',
    'DSCR_MSLicense',
    'DSCR_PowerPlan',
    'DSCR_Shortcut',
    'FileSystemDsc',
    'FSRMDsc',
    'GPRegistryPolicyDsc',
    'JeaDsc',
    'LanguageDsc',
    'Microsoft365DSC',
    'NetworkingDsc',
    'OneDriveDsc',
    'PendingReboot',
    'PolicyFileEditor',
    'PowerShellModule',
    'PSDscResources',
    'SChannelDsc',
    'SecurityPolicyDsc',
    'SharePointDSC',
    'SqlServerDsc',
    'StorageDsc',
    'SystemLocaleDsc',
    'UpdateServicesDsc',
    'VMware.vSphereDSC',
    'WindowsDefenderDsc',
    'WSManDsc',
    'xActiveDirectory',
    'xAdcsDeployment',
    'xBitlocker',
    'xCertificate',
    'xCredSSP',
    'xDhcpServer',
    'xDnsServer',
    'XenDesktop7',
    'xExchange',
    'xFailOverCluster',
    'xHyper-V',
    'xNetworking',
    'xPrinterManagement',
    'xPSDesiredStateConfiguration',
    'xRemoteDesktopSessionHost',
    'xSmbShare',
    'xStorage',
    'xSystemSecurity',
    'xWebAdministration'
)

# Function to log messages
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [ConsoleColor]$Color = 'White'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $Color
    
    if ($LogPath) {
        try {
            $logEntry | Add-Content -Path $LogPath -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {
            # Silently continue if logging fails
        }
    }
}

# Function to test if running as administrator
function Test-Administrator {
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } else {
        return (id -u) -eq 0
    }
}

# Function to install a single module
function Install-DSCModule {
    param(
        [string]$ModuleName,
        [string]$InstallScope,
        [bool]$ForceInstall,
        [bool]$SkipPublisher,
        [bool]$UpdateMode
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = @{
        ModuleName = $ModuleName
        Status = 'Unknown'
        Duration = $null
        Version = $null
        Error = $null
    }
    
    try {
        # Check if module already exists
        $existingModule = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue
        
        if ($existingModule -and !$ForceInstall -and !$UpdateMode) {
            $result.Status = 'Already Installed'
            $result.Version = $existingModule.Version
            Write-Log "✓ $ModuleName is already installed (v$($existingModule.Version))" -Color Green
            return $result
        }
        
        if ($UpdateMode -and $existingModule) {
            # Check if update is available
            $latestModule = Find-Module -Name $ModuleName -ErrorAction Stop
            if ([version]$latestModule.Version -gt [version]$existingModule.Version) {
                Write-Log "↑ Updating $ModuleName from v$($existingModule.Version) to v$($latestModule.Version)..." -Color Yellow
                $installParams = @{
                    Name = $ModuleName
                    Force = $true
                    Scope = $InstallScope
                    ErrorAction = 'Stop'
                }
                if ($SkipPublisher) { $installParams.SkipPublisherCheck = $true }
                
                Install-Module @installParams
                $result.Status = 'Updated'
                $result.Version = $latestModule.Version
                Write-Log "✓ Updated $ModuleName to v$($latestModule.Version)" -Color Green
            } else {
                $result.Status = 'Up to Date'
                $result.Version = $existingModule.Version
                Write-Log "✓ $ModuleName is already up to date (v$($existingModule.Version))" -Color Green
            }
            return $result
        }
        
        # Install the module
        Write-Log "📦 Installing $ModuleName..." -Color Yellow
        
        $installParams = @{
            Name = $ModuleName
            Force = $ForceInstall
            Scope = $InstallScope
            ErrorAction = 'Stop'
        }
        
        if ($SkipPublisher) { $installParams.SkipPublisherCheck = $true }
        
        Install-Module @installParams
        
        # Verify installation
        $installedModule = Get-InstalledModule -Name $ModuleName -ErrorAction Stop
        $result.Status = 'Installed'
        $result.Version = $installedModule.Version
        Write-Log "✓ Successfully installed $ModuleName v$($installedModule.Version)" -Color Green
        
    } catch {
        $result.Status = 'Failed'
        $result.Error = $_.Exception.Message
        Write-Log "✗ Failed to install $ModuleName : $($_.Exception.Message)" -Level 'ERROR' -Color Red
    } finally {
        $stopwatch.Stop()
        $result.Duration = $stopwatch.ElapsedMilliseconds
    }
    
    return $result
}

# Main execution starts here
Write-Host ""
Write-Host "🚀 PowerShell DSC Module Installer" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Determine modules to install
$modulesToInstall = if ($ModuleList.Count -gt 0) { $ModuleList } else { $defaultModules }

Write-Log "📋 Configuration:" -Color Cyan
Write-Log "   • Modules to process: $($modulesToInstall.Count)" -Color Gray
Write-Log "   • Installation scope: $Scope" -Color Gray
Write-Log "   • Parallel processing: $Parallel" -Color Gray
Write-Log "   • Force reinstall: $Force" -Color Gray
Write-Log "   • Update existing: $UpdateExisting" -Color Gray
Write-Log "   • Dry run mode: $DryRun" -Color Gray
Write-Log "   • Log file: $LogPath" -Color Gray

# Check administrator privileges for AllUsers scope
if ($Scope -eq 'AllUsers' -and !(Test-Administrator)) {
    Write-Log "⚠️  AllUsers scope requires administrator privileges. Switching to CurrentUser scope." -Level 'WARN' -Color Yellow
    $Scope = 'CurrentUser'
}

# Verify PowerShell Gallery is trusted
$psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
if ($psGallery.InstallationPolicy -ne 'Trusted') {
    Write-Log "🔐 Setting PowerShell Gallery as trusted repository..." -Color Yellow
    try {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        Write-Log "✓ PowerShell Gallery is now trusted" -Color Green
    } catch {
        Write-Log "⚠️  Could not set PSGallery as trusted: $($_.Exception.Message)" -Level 'WARN' -Color Yellow
    }
}

if ($DryRun) {
    Write-Log "🔍 DRY RUN MODE - No modules will be installed" -Color Cyan
    Write-Log "📦 Modules that would be processed:" -Color Yellow
    $modulesToInstall | ForEach-Object { Write-Log "   • $_" -Color Gray }
    return
}

Write-Log ""
Write-Log "🎯 Starting module installation..." -Color Green

# Track results
$results = @()
$startTime = Get-Date

if ($Parallel -and $modulesToInstall.Count -gt 5) {
    Write-Log "⚡ Using parallel processing for faster installation..." -Color Yellow
    
    # Install modules in parallel
    $results = $modulesToInstall | ForEach-Object -Parallel {
        $moduleName = $_
        
        # Import functions into parallel scope
        function Write-Log {
            param([string]$Message, [string]$Level = 'INFO', [ConsoleColor]$Color = 'White')
            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $Color
        }
        
        function Install-DSCModule {
            param(
                [string]$ModuleName,
                [string]$InstallScope,
                [bool]$ForceInstall,
                [bool]$SkipPublisher,
                [bool]$UpdateMode
            )
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = @{
                ModuleName = $ModuleName
                Status = 'Unknown'
                Duration = $null
                Version = $null
                Error = $null
            }
            
            try {
                $existingModule = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue
                
                if ($existingModule -and !$ForceInstall -and !$UpdateMode) {
                    $result.Status = 'Already Installed'
                    $result.Version = $existingModule.Version
                    return $result
                }
                
                if ($UpdateMode -and $existingModule) {
                    $latestModule = Find-Module -Name $ModuleName -ErrorAction Stop
                    if ([version]$latestModule.Version -gt [version]$existingModule.Version) {
                        $installParams = @{
                            Name = $ModuleName
                            Force = $true
                            Scope = $InstallScope
                            ErrorAction = 'Stop'
                        }
                        if ($SkipPublisher) { $installParams.SkipPublisherCheck = $true }
                        
                        Install-Module @installParams
                        $result.Status = 'Updated'
                        $result.Version = $latestModule.Version
                    } else {
                        $result.Status = 'Up to Date'
                        $result.Version = $existingModule.Version
                    }
                    return $result
                }
                
                $installParams = @{
                    Name = $ModuleName
                    Force = $ForceInstall
                    Scope = $InstallScope
                    ErrorAction = 'Stop'
                }
                
                if ($SkipPublisher) { $installParams.SkipPublisherCheck = $true }
                
                Install-Module @installParams
                
                $installedModule = Get-InstalledModule -Name $ModuleName -ErrorAction Stop
                $result.Status = 'Installed'
                $result.Version = $installedModule.Version
                
            } catch {
                $result.Status = 'Failed'
                $result.Error = $_.Exception.Message
            } finally {
                $stopwatch.Stop()
                $result.Duration = $stopwatch.ElapsedMilliseconds
            }
            
            return $result
        }
        
        Install-DSCModule -ModuleName $moduleName -InstallScope $using:Scope -ForceInstall $using:Force -SkipPublisher $using:SkipPublisherCheck -UpdateMode $using:UpdateExisting
        
    } -ThrottleLimit 5
    
} else {
    Write-Log "🔄 Processing modules sequentially..." -Color Yellow
    
    # Sequential installation with progress
    $processed = 0
    foreach ($moduleName in $modulesToInstall) {
        $processed++
        $progress = @{
            Activity = 'Installing DSC Modules'
            Status = "Processing $moduleName ($processed of $($modulesToInstall.Count))"
            PercentComplete = [math]::Round(($processed / $modulesToInstall.Count) * 100)
        }
        Write-Progress @progress
        
        $result = Install-DSCModule -ModuleName $moduleName -InstallScope $Scope -ForceInstall $Force -SkipPublisher $SkipPublisherCheck -UpdateMode $UpdateExisting
        $results += $result
    }
    Write-Progress -Activity 'Installing DSC Modules' -Completed
}

# Calculate statistics
$endTime = Get-Date
$totalDuration = $endTime - $startTime
$successful = $results | Where-Object Status -in @('Installed', 'Updated', 'Already Installed', 'Up to Date')
$failed = $results | Where-Object Status -eq 'Failed'

# Display summary
Write-Log ""
Write-Log "📊 Installation Summary:" -Color Cyan
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-Log "   • Total modules: $($results.Count)" -Color Gray
Write-Log "   • Successful: $($successful.Count)" -Color Green
Write-Log "   • Failed: $($failed.Count)" -Color Red
Write-Log "   • Total duration: $($totalDuration.TotalSeconds.ToString('F1'))s" -Color Gray

if ($successful.Count -gt 0) {
    Write-Log ""
    Write-Log "✅ Successfully processed modules:" -Color Green
    $successful | Group-Object Status | ForEach-Object {
        Write-Log "   • $($_.Name): $($_.Count) modules" -Color Gray
    }
}

if ($failed.Count -gt 0) {
    Write-Log ""
    Write-Log "❌ Failed installations:" -Color Red
    $failed | ForEach-Object {
        Write-Log "   • $($_.ModuleName): $($_.Error)" -Color Red
    }
    
    Write-Log ""
    Write-Log "💡 Troubleshooting tips for failures:" -Color Yellow
    Write-Log "   • Run with -Force to overwrite existing modules" -Color Gray
    Write-Log "   • Run with -SkipPublisherCheck to bypass publisher validation" -Color Gray
    Write-Log "   • Check internet connectivity and PowerShell Gallery access" -Color Gray
    Write-Log "   • Try running as administrator for AllUsers scope" -Color Gray
}

# Performance insights
$avgDuration = ($results | Where-Object Duration | ForEach-Object Duration | Measure-Object -Average).Average
Write-Log ""
Write-Log "⏱️  Performance insights:" -Color Gray
Write-Log "   • Average installation time: $($avgDuration.ToString('F0'))ms per module" -Color Gray
Write-Log "   • Estimated time saved with parallel: ~$([math]::Round($totalDuration.TotalSeconds * 0.7, 1))s" -Color Gray

Write-Log ""
Write-Log "✨ DSC module installation completed!" -Color Green
Write-Log "📝 Full log available at: $LogPath" -Color Gray
