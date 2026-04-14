<#
.SYNOPSIS
    PowerShell DSC Configuration Validator

.DESCRIPTION
    Validates PowerShell DSC configuration files by parsing syntax and optionally
    attempting full DSC compilation. Syntax validation runs cross-platform (pwsh).
    Full compilation requires Windows with PowerShell 5.1 and DSC modules installed.

.PARAMETER Path
    Root directory to scan for .ps1 files. Defaults to the repository root
    (parent of the directory containing this script).

.PARAMETER Exclude
    Directory names to skip during scan.
    Default: helper-scripts, demo, wip, workspace-templates, Microsoft_Examples

.PARAMETER SyntaxOnly
    Parse files with the PowerShell AST parser only. No DSC modules required.
    Safe to run on Linux/macOS. This is what the CI/CD pipeline uses.

.PARAMETER DryRun
    Show which files would be validated without actually validating them.

.PARAMETER OutputPath
    Temporary directory for compiled MOF files during full compilation.
    Default: $env:TEMP\DSCValidation (cleaned up after each run)

.PARAMETER Export
    Export results to a CSV file in the current directory.

.EXAMPLE
    .\validate-configurations.ps1 -SyntaxOnly
    Validate syntax of all configuration files (cross-platform)

.EXAMPLE
    .\validate-configurations.ps1 -SyntaxOnly -DryRun
    Preview which files would be validated

.EXAMPLE
    .\validate-configurations.ps1
    Full syntax + compilation validation (requires Windows + PowerShell 5.1)

.EXAMPLE
    .\validate-configurations.ps1 -SyntaxOnly -Export
    Validate syntax and export results to CSV

.EXAMPLE
    .\validate-configurations.ps1 -Path .\microsoft\security_baselines -SyntaxOnly
    Validate only a specific subdirectory

.NOTES
    Full compilation mode requires:
    - Windows OS
    - PowerShell 5.1 (not PowerShell 7+)
    - DSC modules installed (run .\install-psgallery-modules.ps1 first)
#>

[CmdletBinding()]
param(
    [string]$Path = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),
    [string[]]$Exclude = @('helper-scripts', 'demo', 'wip', 'workspace-templates', 'Microsoft_Examples'),
    [switch]$SyntaxOnly,
    [switch]$DryRun,
    [string]$OutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'DSCValidation'),
    [switch]$Export
)

# --- Logging helper -------------------------------------------------------

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [ConsoleColor]$Color = 'White'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $Color
}

# --- Main -----------------------------------------------------------------

Write-Host ''
Write-Host '🔍 PowerShell DSC Configuration Validator' -ForegroundColor Cyan
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Cyan

# Collect files
$allFiles = Get-ChildItem -Path $Path -Filter '*.ps1' -Recurse -ErrorAction Stop |
    Where-Object {
        $filePath = $_.FullName
        $excluded = $false
        foreach ($dir in $Exclude) {
            $separator = [System.IO.Path]::DirectorySeparatorChar
            if ($filePath -match "$separator$dir$separator" -or $filePath -match "$separator$dir$([regex]::Escape($separator))") {
                $excluded = $true
                break
            }
            # Also check directory components directly
            $parts = $filePath -split [regex]::Escape($separator)
            if ($parts -contains $dir) {
                $excluded = $true
                break
            }
        }
        -not $excluded
    }

Write-Log "📁 Scan root    : $Path" -Color Cyan
Write-Log "🚫 Excluding    : $($Exclude -join ', ')" -Color Gray
Write-Log "📄 Files found  : $($allFiles.Count)" -Color Cyan
Write-Log "🔧 Mode         : $(if ($SyntaxOnly) { 'Syntax only (cross-platform)' } else { 'Syntax + Compilation (Windows/PS5.1)' })" -Color Cyan

if ($DryRun) {
    Write-Log '' -Color Gray
    Write-Log '🔍 DRY RUN - files that would be validated:' -Color Yellow
    $allFiles | ForEach-Object { Write-Log "   • $($_.FullName)" -Color Gray }
    return
}

# Check compilation prerequisites
$canCompile = $false
if (-not $SyntaxOnly) {
    if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $canCompile = $true
        } else {
            Write-Log '⚠️  Full compilation requires PowerShell 5.1. Falling back to syntax-only mode.' -Level 'WARN' -Color Yellow
            $SyntaxOnly = $true
        }
    } else {
        Write-Log '⚠️  Full compilation requires Windows. Falling back to syntax-only mode.' -Level 'WARN' -Color Yellow
        $SyntaxOnly = $true
    }
}

if ($canCompile) {
    # Clean and recreate output directory
    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Recurse -Force }
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    Write-Log "📂 MOF output   : $OutputPath" -Color Gray
}

Write-Log '' -Color Gray
Write-Log '🎯 Starting validation...' -Color Green

$results = @()
$startTime = Get-Date
$processed = 0

foreach ($file in $allFiles) {
    $processed++
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $result = [PSCustomObject]@{
        FileName            = $file.Name
        Path                = $file.FullName
        SyntaxValid         = $false
        CompiledSuccessfully = $null
        ErrorMessage        = $null
        Duration            = $null
    }

    Write-Progress -Activity 'Validating DSC configurations' `
        -Status "[$processed/$($allFiles.Count)] $($file.Name)" `
        -PercentComplete ([math]::Round(($processed / $allFiles.Count) * 100))

    # Step 1: AST syntax parse (always)
    try {
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $file.FullName, [ref]$null, [ref]$parseErrors
        )

        if ($parseErrors.Count -gt 0) {
            $result.SyntaxValid = $false
            $result.ErrorMessage = ($parseErrors | ForEach-Object { $_.Message }) -join '; '
            Write-Log "✗ SYNTAX  $($file.Name)" -Level 'ERROR' -Color Red
            Write-Log "  $($result.ErrorMessage)" -Level 'ERROR' -Color Red
        } else {
            $result.SyntaxValid = $true
            Write-Log "✓ SYNTAX  $($file.Name)" -Color Green
        }
    } catch {
        $result.SyntaxValid = $false
        $result.ErrorMessage = $_.Exception.Message
        Write-Log "✗ PARSE   $($file.Name): $($_.Exception.Message)" -Level 'ERROR' -Color Red
    }

    # Step 2: DSC compilation (Windows + PS5.1 only)
    if ($canCompile -and $result.SyntaxValid) {
        $configOutputPath = Join-Path $OutputPath $file.BaseName
        $null = New-Item -ItemType Directory -Path $configOutputPath -Force -ErrorAction SilentlyContinue

        try {
            $null = & powershell.exe -NoProfile -NonInteractive -Command "
                . '$($file.FullName)'
                `$configName = (Get-Command -CommandType Configuration | Select-Object -Last 1).Name
                if (`$configName) { & `$configName -OutputPath '$configOutputPath' }
            " 2>&1

            $mofFiles = Get-ChildItem -Path $configOutputPath -Filter '*.mof' -ErrorAction SilentlyContinue
            if ($mofFiles.Count -gt 0) {
                $result.CompiledSuccessfully = $true
                Write-Log "  ✓ COMPILE $($file.Name)" -Color Green
            } else {
                $result.CompiledSuccessfully = $false
                $result.ErrorMessage = 'No MOF file produced'
                Write-Log "  ✗ COMPILE $($file.Name): No MOF produced" -Level 'WARN' -Color Yellow
            }
        } catch {
            $result.CompiledSuccessfully = $false
            $result.ErrorMessage = $_.Exception.Message
            Write-Log "  ✗ COMPILE $($file.Name): $($_.Exception.Message)" -Level 'ERROR' -Color Red
        } finally {
            # Clean up MOF files after each check (they contain machine config data)
            Remove-Item $configOutputPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $stopwatch.Stop()
    $result.Duration = "$($stopwatch.ElapsedMilliseconds)ms"
    $results += $result
}

Write-Progress -Activity 'Validating DSC configurations' -Completed

# Clean up output directory
if ($canCompile -and (Test-Path $OutputPath)) {
    Remove-Item $OutputPath -Recurse -Force -ErrorAction SilentlyContinue
}

# Summary
$endTime = Get-Date
$totalDuration = $endTime - $startTime
$syntaxFailed  = $results | Where-Object { -not $_.SyntaxValid }
$compileFailed = $results | Where-Object { $_.CompiledSuccessfully -eq $false }
$passed        = $results | Where-Object { $_.SyntaxValid -and ($_.CompiledSuccessfully -ne $false) }

Write-Host ''
Write-Host '📊 Validation Summary:' -ForegroundColor Cyan
Write-Host '━━━━━━━━━━━━━━━━━━━━━━' -ForegroundColor Cyan
Write-Log "   • Files validated   : $($results.Count)" -Color Gray
Write-Log "   • Syntax passed     : $($results.Where({ $_.SyntaxValid }).Count)" -Color $(if ($syntaxFailed.Count -eq 0) { 'Green' } else { 'Yellow' })
Write-Log "   • Syntax failed     : $($syntaxFailed.Count)" -Color $(if ($syntaxFailed.Count -eq 0) { 'Green' } else { 'Red' })

if ($canCompile) {
    Write-Log "   • Compiled OK       : $($results.Where({ $_.CompiledSuccessfully -eq $true }).Count)" -Color Green
    Write-Log "   • Compile failed    : $($compileFailed.Count)" -Color $(if ($compileFailed.Count -eq 0) { 'Green' } else { 'Red' })
}

Write-Log "   • Total duration    : $($totalDuration.TotalSeconds.ToString('F1'))s" -Color Gray

if ($syntaxFailed.Count -gt 0) {
    Write-Host ''
    Write-Host '❌ Files with syntax errors:' -ForegroundColor Red
    $syntaxFailed | Format-Table FileName, ErrorMessage -AutoSize -Wrap
}

if ($compileFailed.Count -gt 0) {
    Write-Host ''
    Write-Host '⚠️  Files that failed compilation:' -ForegroundColor Yellow
    $compileFailed | Format-Table FileName, ErrorMessage -AutoSize -Wrap
}

if ($Export) {
    $csvPath = Join-Path $PWD "dsc-validation-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    try {
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "💾 Results exported to: $csvPath" -Color Green
    } catch {
        Write-Log "⚠️  Export failed: $($_.Exception.Message)" -Level 'WARN' -Color Yellow
    }
}

Write-Host ''

$totalFailed = $syntaxFailed.Count + $compileFailed.Count
if ($totalFailed -gt 0) {
    Write-Host "✗ Validation completed with $totalFailed failure(s)." -ForegroundColor Red
    exit 1
} else {
    Write-Host '✨ All configurations passed validation!' -ForegroundColor Green
}
