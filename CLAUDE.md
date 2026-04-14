# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

PowerShell Desired State Configuration (DSC) scripts for enterprise Windows infrastructure automation — Citrix environments, Microsoft security baselines, DoD STIG compliance, and XOAP-specific role configurations.

## Key Commands (PowerShell 5.1 required)

```powershell
# Check available DSC resources
Get-DscResource

# Install all required DSC modules from PowerShell Gallery
.\helper-scripts\install-psgallery-modules.ps1

# Preview what modules would be installed (no changes)
.\helper-scripts\install-psgallery-modules.ps1 -DryRun

# Update existing modules to latest versions
.\helper-scripts\install-psgallery-modules.ps1 -UpdateExisting -Force

# Check for outdated modules
.\helper-scripts\find-outdated-modules.ps1 -NeedUpdateOnly

# Validate all configuration files for syntax errors (cross-platform)
.\helper-scripts\validate-configurations.ps1 -SyntaxOnly

# Full DSC compilation validation (requires Windows + PowerShell 5.1)
.\helper-scripts\validate-configurations.ps1

# Run PSScriptAnalyzer locally (requires PSScriptAnalyzer module)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\.pssa-settings.psd1

# Compile a configuration (dot-source the file, then call the function)
. .\path\to\config.ps1
ConfigurationName

# Apply a compiled configuration
Start-DscConfiguration -Path .\ConfigurationName -Verbose -Wait

# Reset Local Configuration Manager (test first)
.\helper-scripts\reset-lcm.ps1 -DryRun
.\helper-scripts\reset-lcm.ps1
```

## Architecture

### Directory Structure
- [templates/](templates/) — Base template (`xoap-dsc-template.ps1`); start here for new configurations
- [citrix/](citrix/) — Citrix component configs (Delivery Controller, StoreFront, VDA, WEM, UberAgent, etc.)
- [citrix/optimizer/](citrix/optimizer/) — Citrix and VDOT optimizer configurations per OS version
- [microsoft/security_baselines/](microsoft/security_baselines/) — MS security baselines by OS (W2K16–W2K25, W11, Edge, M365)
- [microsoft/avd/](microsoft/avd/) — Azure Virtual Desktop configurations
- [microsoft/rds/](microsoft/rds/) — Remote Desktop Services configurations
- [microsoft/server/](microsoft/server/) — Server role configurations (DNS, IIS, WSUS, DC, etc.)
- [STIG/](STIG/) — DoD STIG compliance configurations (organized by date: january_2023, august_2023)
- [xoap-configs/](xoap-configs/) — XOAP-specific role baselines (consultant, developer, VDI variants)
- [workspace-templates/](workspace-templates/) — Role+variant workspace configurations
- [helper-scripts/](helper-scripts/) — Module management and LCM automation scripts
- [demo/](demo/) — Simple example configurations for testing

### Standard Configuration Pattern

Every configuration follows this structure (see [templates/xoap-dsc-template.ps1](templates/xoap-dsc-template.ps1)):

```powershell
Configuration 'ConfigurationName'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'

    Node 'ConfigurationName'  # Node name always matches Configuration name
    {
        # Resources grouped: features → services → registry/policy
    }
}
ConfigurationName -OutputPath 'C:\ConfigurationName'
```

**Always pin `-ModuleVersion`** in production configurations.

### Naming Conventions
- Microsoft/vendor configs: `[VENDOR]_[PRODUCT]_[VERSION]_[TYPE].ps1` — e.g., `MSTF_SecurityBaseline_W2K22_Computer.ps1`
- XOAP configs: `xoap-[role]-[variant].ps1` — e.g., `xoap-developer-config-vdi.ps1`
- XOAP-prefixed variants: `XOAP_[Product]_[Component].ps1` for updated/enhanced versions

### Key DSC Modules
Security baselines use `GPRegistryPolicyDsc`, `SecurityPolicyDSC`, `AuditPolicyDSC`. XOAP-specific configs use `XOAPBaselineModuleDSC` and `RISBaselineDSC`. Full module list is in [helper-scripts/install-psgallery-modules.ps1](helper-scripts/install-psgallery-modules.ps1).

### Security Baseline Pattern
Registry-heavy configurations use `RegistryPolicyFile` resources with `TargetType = 'ComputerConfiguration'` and `Key`/`ValueName`/`ValueData`/`ValueType` properties.

### Important Warnings
- **Always test in an isolated environment first.** Some configurations make severe security changes that can leave a system unusable.
- All configurations run under PowerShell 5.1 — not PowerShell 7+.
- Citrix configurations require Citrix components to be pre-installed before DSC runs.

## Commit Conventions

Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) and [Semantic Versioning](https://semver.org). Branch/PR naming follows [Git Naming Conventions](https://namingconvention.org/git/). Use the fork-and-pull workflow; keep PRs focused with clear descriptions.
