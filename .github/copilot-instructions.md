# XOAP PowerShell DSC Configurations - AI Coding Instructions

## Project Overview
This repository contains PowerShell Desired State Configuration (DSC) scripts for enterprise infrastructure automation, focusing on Windows systems, Citrix environments, and security baselines. All configurations follow XOAP's Infrastructure as Code patterns.

## Configuration Architecture

### Directory Structure & Purpose
- **`templates/`**: Base DSC template (`xoap-dsc-template.ps1`) - use as starting point for new configurations
- **`citrix/`**: Citrix infrastructure components (Delivery Controller, StoreFront, VDA, etc.)
- **`microsoft/security_baselines/`**: Microsoft security baselines organized by OS version (W2K16, W2K19, W2K22, W11, etc.)
- **`STIG/`**: DoD STIG compliance configurations by date (January 2023, August 2023)
- **`xoap-configs/`**: XOAP-specific baseline configurations (consultant, developer, VDI variants)
- **`demo/`**: Simple demonstration configurations for testing and examples
- **`helper-scripts/`**: Essential automation scripts for module management and LCM operations

### Configuration Naming Convention
Follow this pattern: `[VENDOR]_[PRODUCT]_[VERSION]_[TYPE].ps1`
- Examples: `MSTF_SecurityBaseline_W2K22_Computer.ps1`, `Citrix_Delivery_Controller.ps1`
- XOAP configs use: `xoap-[role]-[variant].ps1` (e.g., `xoap-consultant-config-vdi.ps1`)

## DSC Configuration Patterns

### Standard Configuration Structure
```powershell
Configuration 'ConfigurationName'
{
    # Always specify module versions for production
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
    
    Node 'ConfigurationName'  # Node name matches Configuration name
    {
        # Resources here
    }
}
```

### Module Import Standards
- **Always specify `-ModuleVersion`** for production configurations (see security baselines for examples)
- Common modules: `GPRegistryPolicyDsc`, `SecurityPolicyDSC`, `AuditPolicyDSC`, `ComputerManagementDsc`
- XOAP-specific modules: `XOAPBaselineModuleDSC`, `RISBaselineDSC`

### Resource Naming Pattern
- Use descriptive names: `RegistryPolicyFile 'Registry(POL): HKLM:\Path\To\Key'`
- Windows features: Use exact feature names from `Get-WindowsOptionalFeature`
- Services: Match actual service names for reliability

### Security Baseline Patterns
Security baselines extensively use `RegistryPolicyFile` resources:
```powershell
RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
{
    ValueName = 'SitePerProcess'
    ValueData = 1
    ValueType = 'Dword'
    TargetType = 'ComputerConfiguration'
    Key = 'HKLM:\Software\Policies\Microsoft\Edge'
}
```

### Citrix Configuration Patterns
- Install required Windows features as arrays using foreach loops
- Always configure related services (State = 'Running', StartupType = 'Automatic')
- Group related components (see `Citrix_Delivery_Controller.ps1` for IIS features pattern)

## Development Workflows

### Module Management
Use `helper-scripts/install-psgallery-modules.ps1`:
- Installs all required DSC modules with version management
- Supports parallel installation (`-Parallel`)
- Use `-DryRun` for testing, `-UpdateExisting` for maintenance
- Default comprehensive module list covers all project needs

### LCM Management  
Use `helper-scripts/reset-lcm.ps1`:
- Reset Local Configuration Manager to known state
- Supports backup/restore (`-BackupCurrent`, `-RestoreFromBackup`)
- Multi-computer support with credential handling
- Always test with `-DryRun` before production changes

### Configuration Testing Workflow
1. Check module availability: `Get-DscResource`
2. Install missing modules: `.\helper-scripts\install-psgallery-modules.ps1`
3. Compile configuration: `. .\path\to\config.ps1; ConfigurationName`
4. Apply locally: `Start-DscConfiguration -Path .\ConfigurationName -Verbose -Wait`

## Project-Specific Conventions

### Version Management
- **Critical**: Pin module versions in production (see all security baselines)
- Use semantic versioning for configuration releases
- Document breaking changes between versions

### Testing Requirements
- **Always test in isolated environment first** (per README disclaimer)
- Some configurations make severe security changes
- Use `-WhatIf` equivalent patterns where available

### XOAP Integration
- Configurations integrate with config.XO platform
- Follow [XOAP documentation](https://docs.xoap.io/configuration-management/) for deployment
- Support both local and platform-based execution

### File Organization
- Group related configurations by vendor/technology (citrix/, microsoft/)
- Separate production configurations from examples (demo/, workspace-templates/)
- Use optimizer/ subdirectories for performance-focused configurations

### Error Handling
- DSC resources handle most error conditions automatically
- Focus on prerequisite validation (Windows features, services)
- Log important operations for troubleshooting

## Integration Points

### PowerShell Gallery Dependencies
Configurations depend on external DSC modules from PowerShell Gallery. Critical modules include:
- `GPRegistryPolicyDsc`, `SecurityPolicyDSC`, `AuditPolicyDSC` for security baselines
- `ComputerManagementDsc` for system management  
- `XOAPBaselineModuleDSC`, `RISBaselineDSC` for XOAP-specific functionality

### External Requirements
- PowerShell 5.1+ (Windows Management Framework 5.1 for older systems)
- Appropriate permissions for target systems
- Network access to PowerShell Gallery for module installation
- For Citrix: Citrix components must be pre-installed before DSC configuration

## Common Patterns to Follow
- Node names should match configuration names
- Use `Import-DscResource` with explicit module versions
- Group related resources logically (features, then services, then configuration)
- Prefer built-in DSC resources over custom scripts where possible
- Follow the template in `templates/xoap-dsc-template.ps1` for new configurations