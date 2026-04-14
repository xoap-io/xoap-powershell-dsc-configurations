# Citrix StoreFront Ansible Playbook

## Overview
This Ansible playbook is a direct conversion of the PowerShell DSC configuration `Citrix_StoreFront.ps1`. It configures Windows servers with the necessary features and services required for Citrix StoreFront deployment.

## Conversion Notes

### DSC → Ansible Mapping
| DSC Resource | Ansible Module | Notes |
|--------------|----------------|--------|
| `WindowsFeature` | `ansible.windows.win_feature` | Direct equivalent for installing Windows features |
| `Service` | `ansible.windows.win_service` | Maps service state and startup type |
| `Registry` | `ansible.windows.win_regedit` | Registry key manipulation |

### Key Differences from DSC
1. **Idempotency**: Ansible handles this automatically, similar to DSC
2. **Error Handling**: Enhanced with `ignore_errors` and proper validation
3. **Reporting**: Added detailed status reporting and validation playbook
4. **Reboot Handling**: Explicit reboot management with handlers

## Prerequisites

### Target Systems
- Windows Server 2016 or later
- PowerShell 5.1 or later
- WinRM enabled and configured
- Administrative access

### Control Node Requirements
- Ansible Core 2.12 or later
- Python 3.8 or later
- Required collections (see `requirements.yml`)

## Installation

1. **Install required collections:**
   ```bash
   ansible-galaxy collection install -r requirements.yml
   ```

2. **Configure inventory** (example provided in playbook comments)

3. **Set up Windows authentication** (recommended: use Ansible Vault for passwords)

## Usage

### Basic Execution
```bash
# Run the complete configuration
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml

# Run with vault password
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml --ask-vault-pass

# Dry run (check mode)
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml --check

# Run only validation
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml --tags validation
```

### Advanced Options
```bash
# Limit to specific hosts
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml --limit storefront-server-01

# Verbose output for troubleshooting
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml -vvv

# Skip reboot handler
ansible-playbook -i inventory.yml citrix_storefront_playbook.yml --skip-tags reboot
```

## Features Configured

The playbook installs and configures the following Windows features:
- **IIS Core Features**: Web-Server, Web-WebServer, Web-Default-Doc, Web-Static-Content
- **IIS Security**: Web-Security, Web-Filtering, Web-Basic-Auth, Web-Windows-Auth  
- **IIS Application Development**: Web-App-Dev, Web-Net-Ext45, Web-Asp-Net45, Web-ISAPI-Ext, Web-ISAPI-Filter
- **IIS Management**: Web-Mgmt-Tools, Web-Mgmt-Console, Web-Scripting-Tools
- **.NET Framework**: NET-Framework-45-ASPNET

## Services Managed
- **W3SVC** (IIS): Ensures running with automatic startup
- **CitrixStoreFront**: Ensures running with automatic startup (if present)

## Registry Configuration
- **StoreFront Logging**: Enables logging at `HKLM:\SOFTWARE\Citrix\DeliveryServices\Logging`

## Validation & Reporting
The playbook includes a comprehensive validation section that:
- Verifies all required features are installed
- Checks service status
- Generates a configuration summary report
- Identifies if reboots are required

## Troubleshooting

### Common Issues
1. **WinRM Connection Failures**: Ensure WinRM is properly configured and firewall allows connections
2. **Service Not Found**: CitrixStoreFront service may not exist if StoreFront software isn't pre-installed
3. **Feature Installation Failures**: Check Windows Update status and available features

### Debug Information
The playbook provides extensive debug output including:
- Feature installation results
- Service status information  
- Registry configuration status
- Reboot requirements

## Integration with XOAP Patterns

This playbook follows XOAP Infrastructure as Code patterns:
- **Idempotent operations**: Safe to run multiple times
- **Comprehensive logging**: Detailed status reporting
- **Error handling**: Graceful failure management
- **Validation**: Built-in configuration verification

## Comparison with Original DSC

### Advantages of Ansible Version
- **Cross-platform control**: Manage from Linux/macOS
- **Enhanced reporting**: Better status visibility
- **Flexible targeting**: Easy host selection and grouping
- **Built-in validation**: Comprehensive verification steps

### DSC Advantages
- **Native Windows integration**: Deeper OS integration
- **Local Configuration Manager**: Continuous compliance monitoring
- **PowerShell ecosystem**: Native Windows tooling

## Next Steps
After running this playbook:
1. Install Citrix StoreFront software
2. Configure StoreFront stores and delivery controllers
3. Set up SSL certificates
4. Configure load balancing (if using multiple servers)

## Related Playbooks
Consider creating additional playbooks for:
- Citrix Delivery Controller configuration
- Citrix Virtual Delivery Agent setup
- Complete Citrix environment orchestration