<#
.SYNOPSIS
    PowerShell File Unblocking Utility

.DESCRIPTION
    Unblocks PowerShell files (*.ps1, *.psm1, *.psd1) to resolve execution policy 
    restrictions and security warnings. Supports both recursive and non-recursive 
    processing with detailed progress reporting and error handling.

.PARAMETER Path
    Path to directory containing files to unblock. Default is script root directory.

.PARAMETER Recursive
    Process files recursively in subdirectories. Default is $true.

.PARAMETER FileTypes
    File extensions to process. Default is PowerShell files (ps1, psm1, psd1).

.PARAMETER WhatIf
    Shows what files would be unblocked without actually unblocking them.

.PARAMETER Force
    Suppress confirmation prompts and continue on errors.

.PARAMETER LogPath
    Path for operation log file.

.EXAMPLE
    .\unblock-files.ps1
    Unblock all PowerShell files in script directory recursively

.EXAMPLE
    .\unblock-files.ps1 -Path "C:\Scripts" -Recursive:$false
    Unblock PowerShell files only in specified directory (no subdirectories)

.EXAMPLE
    .\unblock-files.ps1 -WhatIf
    Preview which files would be unblocked

.EXAMPLE
    .\unblock-files.ps1 -FileTypes @("*.ps1", "*.txt", "*.xml")
    Unblock custom file types

.NOTES
    Author: XOAP PowerShell DSC Team
    Version: 2.0
    Requires: PowerShell 3.0+
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ValueFromPipeline = $true)]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$Path = $PSScriptRoot,
    
    [Parameter()]
    [switch]$Recursive = $true,
    
    [Parameter()]
    [string[]]$FileTypes = @("*.ps1", "*.psm1", "*.psd1"),
    
    [Parameter()]
    [switch]$Force,
    
    [Parameter()]
    [string]$LogPath = ""
)

# Function to write log messages
function Write-LogMessage {
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

# Validate parameters
if (!(Test-Path $Path)) {
    Write-Error "Path '$Path' does not exist or is not accessible."
    return
}

# Initialize logging
if (!$LogPath) {
    $LogPath = Join-Path $PWD "unblock-files-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

Write-LogMessage "🔓 PowerShell File Unblocking Utility" -Color Cyan
Write-LogMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-LogMessage "Target Path: $Path" -Color Gray
Write-LogMessage "Recursive: $Recursive" -Color Gray
Write-LogMessage "File Types: $($FileTypes -join ', ')" -Color Gray
Write-LogMessage "What If: $($WhatIfPreference.IsPresent)" -Color Gray

# Get files to process
$getChildItemParams = @{
    Path = $Path
    File = $true
    Include = $FileTypes
    ErrorAction = 'SilentlyContinue'
}

if ($Recursive) {
    $getChildItemParams.Recurse = $true
}

Write-LogMessage "🔍 Scanning for files to unblock..." -Color Yellow

try {
    $filesToProcess = Get-ChildItem @getChildItemParams
    
    if (!$filesToProcess) {
        Write-LogMessage "✅ No files found matching criteria" -Color Green
        return
    }
    
    Write-LogMessage "📊 Found $($filesToProcess.Count) file(s) to process" -Color Green
    
} catch {
    Write-LogMessage "❌ Error scanning files: $($_.Exception.Message)" -Level 'ERROR' -Color Red
    return
}

# Process files
$processed = 0
$successful = 0
$failed = 0
$skipped = 0

foreach ($file in $filesToProcess) {
    $processed++
    $relativePath = $file.FullName.Replace($Path, '').TrimStart('\', '/')
    
    # Show progress for large operations
    if ($filesToProcess.Count -gt 10) {
        $percentComplete = [math]::Round(($processed / $filesToProcess.Count) * 100)
        Write-Progress -Activity "Unblocking Files" -Status "Processing $relativePath" -PercentComplete $percentComplete
    }
    
    try {
        # Check if file is already unblocked (has Zone.Identifier stream)
        $hasZoneId = $false
        try {
            $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue
            $hasZoneId = $streams | Where-Object Stream -eq 'Zone.Identifier'
        } catch {
            # Stream operations may not be supported on all file systems
        }
        
        if (!$hasZoneId) {
            Write-LogMessage "⏭️  Skipping $relativePath (already unblocked)" -Color Gray
            $skipped++
            continue
        }
        
        if ($PSCmdlet.ShouldProcess($file.FullName, "Unblock File")) {
            Unblock-File -Path $file.FullName -ErrorAction Stop
            Write-LogMessage "✅ Unblocked: $relativePath" -Color Green
            $successful++
        } else {
            Write-LogMessage "🔍 Would unblock: $relativePath" -Color Cyan
        }
        
    } catch {
        Write-LogMessage "❌ Failed to unblock $relativePath`: $($_.Exception.Message)" -Level 'ERROR' -Color Red
        $failed++
        
        if (!$Force) {
            $continue = Read-Host "Continue processing remaining files? (y/N)"
            if ($continue -notmatch '^[Yy]') {
                Write-LogMessage "🛑 Operation cancelled by user" -Color Yellow
                break
            }
        }
    }
}

# Clean up progress bar
if ($filesToProcess.Count -gt 10) {
    Write-Progress -Activity "Unblocking Files" -Completed
}

# Summary
Write-LogMessage "" -Color White
Write-LogMessage "📊 Operation Summary:" -Color Cyan
Write-LogMessage "━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-LogMessage "Total files found: $($filesToProcess.Count)" -Color Gray
Write-LogMessage "Successfully unblocked: $successful" -Color Green
Write-LogMessage "Already unblocked: $skipped" -Color Gray
Write-LogMessage "Failed: $failed" -Color Red

if ($failed -gt 0) {
    Write-LogMessage "" -Color White
    Write-LogMessage "💡 Troubleshooting tips:" -Color Yellow
    Write-LogMessage "• Run as Administrator for system-protected files" -Color Gray
    Write-LogMessage "• Check file permissions and ownership" -Color Gray
    Write-LogMessage "• Ensure files are not in use by other processes" -Color Gray
    Write-LogMessage "• Use -Force parameter to continue on errors" -Color Gray
}

Write-LogMessage "" -Color White
if ($WhatIfPreference.IsPresent) {
    Write-LogMessage "🔍 What-If mode completed - no files were actually unblocked" -Color Cyan
} else {
    Write-LogMessage "✨ File unblocking operation completed!" -Color Green
}

Write-LogMessage "📝 Full log available at: $LogPath" -Color Gray
