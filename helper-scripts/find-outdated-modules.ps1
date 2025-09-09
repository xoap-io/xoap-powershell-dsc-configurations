<#
.SYNOPSIS
    PowerShell Module Update Checker - Optimized for performance and reliability

.DESCRIPTION
    Efficiently checks installed PowerShell modules against PowerShell Gallery
    to identify outdated modules that need updates. Supports parallel processing
    and provides detailed reporting with update recommendations.

.PARAMETER NeedUpdateOnly
    Only show modules that need updates (hide up-to-date modules)

.PARAMETER Repository
    Specify repository to check against (default: PSGallery)

.PARAMETER Parallel
    Use parallel processing for faster checks (default: enabled)

.PARAMETER Export
    Export results to CSV file

.PARAMETER OutputPath
    Path for exported CSV file (default: current directory)

.EXAMPLE
    .\find-outdated-modules.ps1
    Check all installed modules from PSGallery

.EXAMPLE
    .\find-outdated-modules.ps1 -NeedUpdateOnly
    Show only modules that need updates

.EXAMPLE
    .\find-outdated-modules.ps1 -Export -OutputPath "C:\Reports\module-updates.csv"
    Export results to CSV file

.NOTES
    Optimized for cross-platform compatibility and performance
#>

[CmdletBinding()]
param(
    [switch]$NeedUpdateOnly,
    [string]$Repository = 'PSGallery',
    [switch]$Parallel = $true,
    [switch]$Export,
    [string]$OutputPath = (Join-Path $PWD "module-update-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv")
)

# Enhanced function with better error handling and performance
function Test-GalleryModuleUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [version]$Version,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Repository = 'PSGallery',

        [switch]$NeedUpdateOnly
    )
    
    process {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = $null
        
        try {
            Write-Verbose "Checking module: $Name (v$Version)"
            
            # Use Find-Module for more reliable version checking
            $latestModule = Find-Module -Name $Name -Repository $Repository -ErrorAction Stop
            $latestVersion = [version]$latestModule.Version
            $needsUpdate = $latestVersion -gt $Version
            
            # Calculate version difference
            $versionDiff = @{
                Major = $latestVersion.Major - $Version.Major
                Minor = $latestVersion.Minor - $Version.Minor
                Build = $latestVersion.Build - $Version.Build
            }
            
            # Determine update priority
            $updatePriority = if ($versionDiff.Major -gt 0) { 'High' }
                             elseif ($versionDiff.Minor -gt 0) { 'Medium' } 
                             else { 'Low' }
            
            if ($needsUpdate -or !$NeedUpdateOnly.IsPresent) {
                $result = [PSCustomObject]@{
                    ModuleName = $Name
                    CurrentVersion = $Version.ToString()
                    LatestVersion = $latestVersion.ToString()
                    NeedsUpdate = $needsUpdate
                    UpdatePriority = if ($needsUpdate) { $updatePriority } else { 'N/A' }
                    VersionsBehind = if ($needsUpdate) { 
                        "$($versionDiff.Major).$($versionDiff.Minor).$($versionDiff.Build)" 
                    } else { 'N/A' }
                    Repository = $Repository
                    CheckDuration = "$($stopwatch.ElapsedMilliseconds)ms"
                    Author = $latestModule.Author
                    Description = $latestModule.Description.Substring(0, [Math]::Min(100, $latestModule.Description.Length))
                    PublishedDate = $latestModule.PublishedDate
                    Status = if ($needsUpdate) { '⚠️ Update Available' } else { '✅ Up to Date' }
                }
            }
        }
        catch {
            Write-Warning "Failed to check module '$Name': $($_.Exception.Message)"
            
            # Fallback to web scraping method
            try {
                Write-Verbose "Falling back to web scraping for module: $Name"
                $url = "https://www.powershellgallery.com/packages/$Name"
                $response = Invoke-WebRequest -Uri $url -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -ErrorVariable webError
                
                if ($webError) {
                    [version]$latestVersion = Split-Path -Path $webError.InnerException.Response.Headers.Location -Leaf
                    $needsUpdate = $latestVersion -gt $Version
                    
                    if ($needsUpdate -or !$NeedUpdateOnly.IsPresent) {
                        $result = [PSCustomObject]@{
                            ModuleName = $Name
                            CurrentVersion = $Version.ToString()
                            LatestVersion = $latestVersion.ToString()
                            NeedsUpdate = $needsUpdate
                            UpdatePriority = 'Unknown'
                            VersionsBehind = 'Unknown'
                            Repository = $Repository
                            CheckDuration = "$($stopwatch.ElapsedMilliseconds)ms"
                            Author = 'Unknown'
                            Description = 'Failed to retrieve details'
                            PublishedDate = 'Unknown'
                            Status = if ($needsUpdate) { '⚠️ Update Available (Limited Info)' } else { '✅ Up to Date' }
                        }
                    }
                }
            }
            catch {
                Write-Warning "Both methods failed for module '$Name'"
                $result = [PSCustomObject]@{
                    ModuleName = $Name
                    CurrentVersion = $Version.ToString()
                    LatestVersion = 'Error'
                    NeedsUpdate = $false
                    UpdatePriority = 'Error'
                    VersionsBehind = 'Error'
                    Repository = $Repository
                    CheckDuration = "$($stopwatch.ElapsedMilliseconds)ms"
                    Author = 'Error'
                    Description = 'Failed to check for updates'
                    PublishedDate = 'Error'
                    Status = '❌ Check Failed'
                }
            }
        }
        finally {
            $stopwatch.Stop()
        }
        
        return $result
    }
}

# Main execution
Write-Host "🔍 PowerShell Module Update Checker" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Get installed modules
Write-Host "📦 Discovering installed modules from $Repository..." -ForegroundColor Yellow
$installedModules = Get-InstalledModule | Where-Object Repository -EQ $Repository

if (-not $installedModules) {
    Write-Host "❌ No modules found from repository '$Repository'" -ForegroundColor Red
    return
}

Write-Host "📊 Found $($installedModules.Count) modules to check" -ForegroundColor Green
Write-Host ""

# Progress tracking
$progress = @{
    Activity = 'Checking module updates'
    Status = 'Initializing...'
    PercentComplete = 0
}

$results = @()
$processed = 0

if ($Parallel -and $installedModules.Count -gt 5) {
    Write-Host "⚡ Using parallel processing for faster checks..." -ForegroundColor Yellow
    
    # Process modules in parallel for better performance
    $results = $installedModules | ForEach-Object -Parallel {
        $module = $_
        $using:VerbosePreference = $VerbosePreference
        
        # Import the function in the parallel scope
        function Test-GalleryModuleUpdate {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
                [string]$Name,
                [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
                [version]$Version,
                [Parameter(ValueFromPipelineByPropertyName)]
                [string]$Repository = 'PSGallery',
                [switch]$NeedUpdateOnly
            )
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            try {
                $latestModule = Find-Module -Name $Name -Repository $Repository -ErrorAction Stop
                $latestVersion = [version]$latestModule.Version
                $needsUpdate = $latestVersion -gt $Version
                
                $versionDiff = @{
                    Major = $latestVersion.Major - $Version.Major
                    Minor = $latestVersion.Minor - $Version.Minor
                    Build = $latestVersion.Build - $Version.Build
                }
                
                $updatePriority = if ($versionDiff.Major -gt 0) { 'High' }
                                 elseif ($versionDiff.Minor -gt 0) { 'Medium' } 
                                 else { 'Low' }
                
                if ($needsUpdate -or !$NeedUpdateOnly.IsPresent) {
                    return [PSCustomObject]@{
                        ModuleName = $Name
                        CurrentVersion = $Version.ToString()
                        LatestVersion = $latestVersion.ToString()
                        NeedsUpdate = $needsUpdate
                        UpdatePriority = if ($needsUpdate) { $updatePriority } else { 'N/A' }
                        VersionsBehind = if ($needsUpdate) { 
                            "$($versionDiff.Major).$($versionDiff.Minor).$($versionDiff.Build)" 
                        } else { 'N/A' }
                        Repository = $Repository
                        CheckDuration = "$($stopwatch.ElapsedMilliseconds)ms"
                        Author = $latestModule.Author
                        Description = $latestModule.Description.Substring(0, [Math]::Min(100, $latestModule.Description.Length))
                        PublishedDate = $latestModule.PublishedDate
                        Status = if ($needsUpdate) { '⚠️ Update Available' } else { '✅ Up to Date' }
                    }
                }
            }
            catch {
                return [PSCustomObject]@{
                    ModuleName = $Name
                    CurrentVersion = $Version.ToString()
                    LatestVersion = 'Error'
                    NeedsUpdate = $false
                    UpdatePriority = 'Error'
                    VersionsBehind = 'Error'
                    Repository = $Repository
                    CheckDuration = "$($stopwatch.ElapsedMilliseconds)ms"
                    Author = 'Error'
                    Description = 'Failed to check for updates'
                    PublishedDate = 'Error'
                    Status = '❌ Check Failed'
                }
            }
            finally {
                $stopwatch.Stop()
            }
        }
        
        Test-GalleryModuleUpdate -Name $module.Name -Version $module.Version -Repository $using:Repository -NeedUpdateOnly:$using:NeedUpdateOnly
    } -ThrottleLimit 10
} else {
    Write-Host "🔄 Processing modules sequentially..." -ForegroundColor Yellow
    
    # Sequential processing with progress bar
    foreach ($module in $installedModules) {
        $processed++
        $progress.Status = "Checking $($module.Name)..."
        $progress.PercentComplete = [math]::Round(($processed / $installedModules.Count) * 100)
        Write-Progress @progress
        
        $result = Test-GalleryModuleUpdate -Name $module.Name -Version $module.Version -Repository $Repository -NeedUpdateOnly:$NeedUpdateOnly
        if ($result) {
            $results += $result
        }
    }
    Write-Progress -Activity 'Checking module updates' -Completed
}

# Filter results
$results = $results | Where-Object { $_ -ne $null }

if (-not $results) {
    Write-Host "✅ All modules are up to date!" -ForegroundColor Green
    return
}

# Sort results by update priority and name
$results = $results | Sort-Object @{
    Expression = { 
        switch ($_.UpdatePriority) {
            'High' { 1 }
            'Medium' { 2 }
            'Low' { 3 }
            default { 4 }
        }
    }
}, ModuleName

# Display results
Write-Host ""
Write-Host "📋 Module Update Report:" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

$updatesNeeded = $results | Where-Object NeedsUpdate -eq $true
$upToDate = $results | Where-Object NeedsUpdate -eq $false

Write-Host "📊 Summary:" -ForegroundColor Yellow
Write-Host "   • Modules checked: $($results.Count)" -ForegroundColor Gray
Write-Host "   • Updates available: $($updatesNeeded.Count)" -ForegroundColor Red
Write-Host "   • Up to date: $($upToDate.Count)" -ForegroundColor Green
Write-Host ""

if ($updatesNeeded.Count -gt 0) {
    Write-Host "⚠️  Modules needing updates:" -ForegroundColor Red
    $updatesNeeded | Format-Table ModuleName, CurrentVersion, LatestVersion, UpdatePriority, Status -AutoSize
    
    Write-Host ""
    Write-Host "💡 Quick update commands:" -ForegroundColor Yellow
    Write-Host "   • Update all: Update-Module" -ForegroundColor Gray
    Write-Host "   • Update specific: Update-Module -Name 'ModuleName'" -ForegroundColor Gray
    Write-Host "   • Update with force: Update-Module -Name 'ModuleName' -Force" -ForegroundColor Gray
}

if (!$NeedUpdateOnly -and $upToDate.Count -gt 0) {
    Write-Host ""
    Write-Host "✅ Up-to-date modules:" -ForegroundColor Green
    $upToDate | Format-Table ModuleName, CurrentVersion, Author -AutoSize
}

# Export functionality
if ($Export) {
    Write-Host ""
    Write-Host "💾 Exporting results to CSV..." -ForegroundColor Yellow
    
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "✅ Report exported to: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export CSV: $($_.Exception.Message)"
    }
}

# Performance summary
$totalDuration = ($results | Where-Object { $_.CheckDuration -match '\d+' } | 
                  ForEach-Object { [int]($_.CheckDuration -replace '\D') } | 
                  Measure-Object -Sum).Sum

Write-Host ""
Write-Host "⏱️  Performance: Total check time ~$($totalDuration)ms" -ForegroundColor Gray
Write-Host "✨ Module update check completed!" -ForegroundColor Green
  