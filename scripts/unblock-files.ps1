# Enhanced file unblocking script for Apple ARM systems
# This script resolves DSC configuration block errors

param(
    [string]$Path = $PSScriptRoot,
    [switch]$Recursive = $true
)

Write-Host "Unblocking files for Apple ARM PowerShell DSC compatibility..." -ForegroundColor Green

# Unblock all PowerShell files in the specified path
if ($Recursive) {
    Get-ChildItem -Path $Path -File -Recurse -Include "*.ps1", "*.psm1", "*.psd1" | ForEach-Object {
        Write-Host "Unblocking: $($_.FullName)" -ForegroundColor Yellow
        Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue
    }
} else {
    Get-ChildItem -Path $Path -File -Include "*.ps1", "*.psm1", "*.psd1" | ForEach-Object {
        Write-Host "Unblocking: $($_.FullName)" -ForegroundColor Yellow
        Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue
    }
}

# Set execution policy for current user (ARM compatibility)
try {
    Write-Host "Setting execution policy for ARM compatibility..." -ForegroundColor Green
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Host "✅ Execution policy set to RemoteSigned for CurrentUser" -ForegroundColor Green
} catch {
    Write-Warning "Could not set execution policy: $($_.Exception.Message)"
}

Write-Host "✅ File unblocking complete!" -ForegroundColor Green
