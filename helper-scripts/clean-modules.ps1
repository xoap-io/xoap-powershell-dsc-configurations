<#
.SYNOPSIS
    PowerShell Module Cleanup Tool - Optimized for cross-platform compatibility

.DESCRIPTION
    Interactive tool to safely remove PowerShell modules from all module paths.
    Supports both Windows and Unix-like systems (macOS, Linux).
    Provides detailed information about modules before removal.

.PARAMETER WhatIf
    Shows what would be removed without actually deleting anything

.PARAMETER Force
    Skip confirmation dialogs (use with caution)

.EXAMPLE
    .\clean-modules.ps1
    Interactive module cleanup with confirmations

.EXAMPLE
    .\clean-modules.ps1 -WhatIf
    Preview what would be removed without actually deleting

.EXAMPLE
    .\clean-modules.ps1 -Force
    Remove selected modules without additional confirmation
#>

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Force
)

# Cross-platform path separator handling
$pathSeparator = if ($IsWindows -or $env:OS -eq "Windows_NT") { ';' } else { ':' }

Write-Host "🔍 PowerShell Module Cleanup Tool" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

# Get all PowerShell module paths
$paths = $env:PSModulePath -split $pathSeparator | Where-Object { 
    $_ -and (Test-Path $_) 
}

Write-Host "📂 Scanning module paths:" -ForegroundColor Yellow
$paths | ForEach-Object { Write-Host "   • $_" -ForegroundColor Gray }
Write-Host ""

# Find all module directories with enhanced information
Write-Host "🔎 Discovering modules..." -ForegroundColor Yellow
$modules = @()

foreach ($path in $paths) {
    try {
        $pathModules = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | 
            ForEach-Object {
                $moduleInfo = @{
                    Name = $_.Name
                    Path = $_.FullName
                    Parent = $_.Parent.FullName
                    Size = $null
                    Version = "Unknown"
                    LastWrite = $_.LastWriteTime
                }
                
                # Calculate directory size
                try {
                    $size = (Get-ChildItem -Path $_.FullName -Recurse -File -ErrorAction SilentlyContinue | 
                             Measure-Object -Property Length -Sum).Sum
                    $moduleInfo.Size = if ($size) { 
                        "{0:N2} MB" -f ($size / 1MB) 
                    } else { "0 MB" }
                } catch {
                    $moduleInfo.Size = "Unknown"
                }
                
                # Try to get module version from manifest
                $manifestPath = Join-Path $_.FullName "$($_.Name).psd1"
                if (Test-Path $manifestPath) {
                    try {
                        $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction SilentlyContinue
                        if ($manifest.ModuleVersion) {
                            $moduleInfo.Version = $manifest.ModuleVersion
                        }
                    } catch {
                        # Silently continue if manifest can't be read
                    }
                }
                
                [PSCustomObject]$moduleInfo
            }
        
        $modules += $pathModules
    } catch {
        Write-Warning "Could not access path: $path - $($_.Exception.Message)"
    }
}

if (-not $modules) {
    Write-Host "✅ No modules found to clean up!" -ForegroundColor Green
    return
}

# Sort modules by name for better organization
$modules = $modules | Sort-Object -Property Name

Write-Host "📊 Found $($modules.Count) modules total" -ForegroundColor Green
Write-Host ""

# Cross-platform module selection
$selectedModules = @()

if ($Force) {
    Write-Warning "Force mode enabled - all modules will be marked for removal!"
    $selectedModules = $modules
} elseif (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
    # Use GridView on Windows/systems that support it
    Write-Host "🖱️  Opening module selection window..." -ForegroundColor Yellow
    
    $selectedModules = $modules | 
        Select-Object -Property Name, Version, Size, Parent, @{N='LastModified';E={$_.LastWrite.ToString('yyyy-MM-dd')}}, Path |
        Out-GridView -Title "Select modules to remove (CTRL+Click for multiple)" -PassThru
    
    if ($selectedModules) {
        Write-Host "⚠️  Final confirmation..." -ForegroundColor Yellow
        $confirmedModules = $selectedModules |
            Out-GridView -Title "FINAL CONFIRMATION: These modules will be PERMANENTLY deleted! Select all and click OK to confirm." -PassThru
        $selectedModules = $confirmedModules
    }
} else {
    # Fallback for systems without GridView (macOS, Linux)
    Write-Host "📋 Available modules:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $modules.Count; $i++) {
        $module = $modules[$i]
        Write-Host ("{0,3}. {1} (v{2}) - {3} - {4}" -f 
            ($i + 1), 
            $module.Name, 
            $module.Version, 
            $module.Size,
            $module.Parent) -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Enter module numbers to remove (comma-separated, e.g., 1,3,5-7): " -NoNewline -ForegroundColor Yellow
    $selection = Read-Host
    
    if ($selection) {
        $indices = @()
        $selection -split ',' | ForEach-Object {
            $range = $_.Trim()
            if ($range -match '^(\d+)-(\d+)$') {
                # Handle ranges like 5-7
                $start = [int]$matches[1] - 1
                $end = [int]$matches[2] - 1
                $indices += $start..$end
            } elseif ($range -match '^\d+$') {
                # Handle single numbers
                $indices += [int]$range - 1
            }
        }
        
        $selectedModules = $indices | ForEach-Object { 
            if ($_ -ge 0 -and $_ -lt $modules.Count) { 
                $modules[$_] 
            }
        }
    }
}

if (-not $selectedModules) {
    Write-Host "❌ No modules selected for removal." -ForegroundColor Yellow
    return
}

# Display removal summary
Write-Host ""
Write-Host "📋 Modules marked for removal:" -ForegroundColor Red
$selectedModules | ForEach-Object {
    Write-Host "   🗑️  $($_.Name) (v$($_.Version)) - $($_.Size)" -ForegroundColor Red
    Write-Host "      Path: $($_.Path)" -ForegroundColor Gray
}

$totalSize = ($selectedModules | Where-Object { $_.Size -match '[\d.]+' } | 
              ForEach-Object { [double]($_.Size -replace '[^0-9.]', '') } | 
              Measure-Object -Sum).Sum

Write-Host ""
Write-Host "💾 Total space to be freed: ~$($totalSize.ToString('N2')) MB" -ForegroundColor Yellow

# Final confirmation (unless Force is used)
if (-not $Force) {
    Write-Host ""
    Write-Host "⚠️  WARNING: This action cannot be undone!" -ForegroundColor Red
    $confirmation = Read-Host "Type 'DELETE' to confirm removal"
    
    if ($confirmation -ne 'DELETE') {
        Write-Host "❌ Operation cancelled." -ForegroundColor Yellow
        return
    }
}

# Perform removal
Write-Host ""
Write-Host "🗑️  Removing selected modules..." -ForegroundColor Yellow

$removed = 0
$failed = 0

foreach ($module in $selectedModules) {
    try {
        if ($WhatIf) {
            Write-Host "   What if: Would remove $($module.Name) from $($module.Path)" -ForegroundColor Cyan
        } else {
            Write-Host "   Removing: $($module.Name)..." -NoNewline
            Remove-Item -Path $module.Path -Recurse -Force -ErrorAction Stop
            Write-Host " ✅" -ForegroundColor Green
            $removed++
        }
    } catch {
        Write-Host " ❌" -ForegroundColor Red
        Write-Warning "Failed to remove $($module.Name): $($_.Exception.Message)"
        $failed++
    }
}

# Summary
Write-Host ""
Write-Host "📊 Cleanup Summary:" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "   🔍 What-If mode: $($selectedModules.Count) modules would be removed" -ForegroundColor Cyan
} else {
    Write-Host "   ✅ Successfully removed: $removed modules" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "   ❌ Failed to remove: $failed modules" -ForegroundColor Red
    }
    Write-Host "   💾 Estimated space freed: ~$($totalSize.ToString('N2')) MB" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "✨ Module cleanup completed!" -ForegroundColor Green
  