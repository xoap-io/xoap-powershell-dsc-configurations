# Missing Configurations — Design Spec

**Date:** 2026-04-08
**Scope:** Add ~30 new DSC configuration files across six areas to fill coverage gaps in the repo.

---

## 1. Security Baselines

### New directories under `microsoft/security_baselines/`

| Directory | Contents |
|---|---|
| `microsoft_w10_full/` | Full Windows 10 baseline (was only update baseline) |
| `microsoft_w11_23h2/` | Windows 11 23H2 baseline |
| `microsoft_w11_24h2/` | Windows 11 24H2 baseline |
| `microsoft_edge_v130/` | Microsoft Edge v130 baseline (replaces v107) |
| `microsoft_m365_apps_2306/` | M365 Apps 2306 baseline (replaces 2206) |

### Files per Windows version (W10 full, W11 23H2, W11 24H2)

Each version gets the same split as W2K22/W2K25:

| Suffix | Purpose |
|---|---|
| `_Computer` | Main computer hardening — registry, audit, security policies |
| `_Bitlocker` | BitLocker drive encryption settings |
| `_Defender_Antivirus` | Windows Defender AV policies |
| `_Credential_Guard` | Virtualization-based security / Credential Guard |
| `_Domain_Security` | Account lockout, password policy, Kerberos settings |

### Files for Edge and M365

- `MSTF_SecurityBaseline_Edge_v130_Computer.ps1` — browser security policies (SmartScreen, extension control, sandbox settings, update policy)
- `MSTF_SecurityBaseline_M365Apps_2306_Computer.ps1` — macro policy, add-in control, telemetry, update channel settings

### DSC modules used (all pinned)

```powershell
Import-DscResource -ModuleName 'GPRegistryPolicyDsc'   -ModuleVersion '1.2.0'
Import-DscResource -ModuleName 'AuditPolicyDSC'        -ModuleVersion '1.4.0.0'
Import-DscResource -ModuleName 'SecurityPolicyDSC'     -ModuleVersion '2.10.0.0'
```

### Naming convention

`MSTF_SecurityBaseline_[OS]_[TYPE].ps1` — Configuration name, Node name, and filename all match.

Examples:
- `MSTF_SecurityBaseline_W11_23H2_Computer.ps1`
- `MSTF_SecurityBaseline_W11_24H2_Bitlocker.ps1`
- `MSTF_SecurityBaseline_W10_Defender_Antivirus.ps1`

---

## 2. STIG Updates

### New directory: `STIG/dod_stig_2024/`

Follows the August 2023 consolidation pattern: combined MS+DC files, no separate per-role files.

| File | Versions covered |
|---|---|
| `DoD_Windows_10_STIG_Computer_v2r7.ps1` | Windows 10 v2r7 |
| `DoD_Windows_11_STIG_Computer_v2r1.ps1` | Windows 11 v2r1 |
| `DoD_WinSvr_2022_MS_and_DC_STIG_Computer_v2r1.ps1` | Server 2022 Member Server + Domain Controller |
| `DoD_WinSvr_2025_MS_and_DC_STIG_Computer_v1r1.ps1` | Server 2025 Member Server + Domain Controller |
| `DoD_Microsoft_Edge_STIG_Computer_v2r1.ps1` | Edge v2r1 |
| `DoD_Office_2019-M365_Apps_STIG_Computer_v3r1.ps1` | M365 Apps v3r1 |
| `DoD_Microsoft_Defender_Antivirus_STIG_Computer_v3r1.ps1` | Defender AV v3r1 |
| `DoD_Google_Chrome_STIG_Computer_v3r1.ps1` | Chrome v3r1 |
| `DoD_Mozilla_Firefox_STIG_Computer_v6r6.ps1` | Firefox v6r6 |
| `DoD_Windows_Firewall_STIG_Computer_v2r1.ps1` | Windows Firewall v2r1 |

### DSC modules used (all pinned)

Same as security baselines: `GPRegistryPolicyDsc`, `AuditPolicyDSC`, `SecurityPolicyDSC`.

### Naming convention

`DoD_[Product]_STIG_Computer_v[X]r[Y].ps1` — consistent with existing august_2023 files.

---

## 3. Citrix

### `citrix/optimizer/XOAP_W11_23H2_Citrix_Optimizer.ps1`

Port of `XOAP_W11_24H2_Citrix_Optimizer.ps1` with 23H2-specific adjustments:
- Same service disablement and registry optimization pattern
- Adjusted for Windows 11 23H2 feature set (no feature removals from 24H2, minor service differences)

### `citrix/XOAP_Citrix_UberAgent_W2K25.ps1`

Based on the existing `Citrix_UberAgent.ps1` (functional original), adapted for Windows Server 2025:
- Service configuration (UberAgentService)
- Registry settings for agent configuration
- Log path and temp directory configuration for Server 2025 paths
- Uses `ComputerManagementDsc -ModuleVersion '10.0.0'`

---

## 4. AVD Session Host

### `microsoft/avd/XOAP_AVD_W11_24H2_SessionHost.ps1`

Main session host hardening and optimization. Covers:
- Teams optimization registry settings (media optimization, WebRTC)
- Windows Update for Business policies (defer feature updates, quality updates)
- Power/sleep disabled for session hosts
- Start menu and search hardening
- RemoteFX/GPU policies for multi-session
- Clipboard and drive redirection policy
- Time zone redirection

### `microsoft/avd/XOAP_AVD_W11_24H2_FSLogix.ps1`

FSLogix profile container configuration. Covers:
- Profile container enabled/path settings
- VHD location and naming
- Profile cleanup on logoff
- Disk compaction settings
- Office container settings
- Concurrent session handling

**DSC modules:** `ComputerManagementDsc -ModuleVersion '10.0.0'`, `GPRegistryPolicyDsc -ModuleVersion '1.2.0'`

---

## 5. RDS Session Hosts

### `microsoft/rds/XOAP_RDS_W2K22_SessionHost.ps1`
### `microsoft/rds/XOAP_RDS_W2K25_SessionHost.ps1`

Both cover:
- Windows features: Remote Desktop Services, RDS-RD-Server
- NLA enforcement
- Encryption level (High)
- Session time limits (idle disconnect, active session max)
- Shadow session permissions
- RDS licensing mode (Per User / Per Device registry setting)
- Clipboard, drive, printer redirection policies
- RemoteApp settings

W2K25 variant uses updated feature names where they differ from W2K22.

**DSC modules:** `PSDesiredStateConfiguration`, `ComputerManagementDsc -ModuleVersion '10.0.0'`, `SecurityPolicyDSC -ModuleVersion '2.10.0.0'`

---

## 6. Server Roles

### `microsoft/server/XOAP_ADFS_Server.ps1`

- Windows features: ADFS-Federation, Web-Server (IIS prereq)
- AdfsDsc module for farm configuration
- Certificate configuration pointers (CertificateDsc)
- Service: adfssrv (Running, Automatic)

### `microsoft/server/XOAP_DHCP_Server.ps1`

- Windows feature: DHCP
- xDhcpServer module: scope, exclusion range, DNS settings, lease duration
- Service: DHCPServer (Running, Automatic)
- DHCP authorization in AD (registry marker)

### `microsoft/server/XOAP_ADCS_Server.ps1`

- Windows features: ADCS-Cert-Authority, ADCS-Web-Enrollment
- xAdcsDeployment module: CA type (EnterpriseRootCA), crypto settings
- Service: CertSvc (Running, Automatic)
- IIS bindings for web enrollment

### `microsoft/server/XOAP_FileServer_DFS.ps1`

- Windows features: FS-FileServer, FS-DFS-Namespace, FS-DFS-Replication, FS-Resource-Manager
- DFSDsc: namespace root, folder targets
- SmbShare: share creation with ACLs
- FSRMDsc: quota and file screen policies

### `microsoft/server/XOAP_HyperV_Host.ps1`

- Windows features: Hyper-V, Hyper-V-Tools, Hyper-V-PowerShell, Hyper-V-Management-Clients
- xHyper-V: default VM paths, virtual switch configuration
- Service: vmms (Running, Automatic)
- Memory, processor, and integration services defaults

### `microsoft/server/XOAP_SQLServer_Baseline.ps1`

- SqlServerDsc: server configuration (max memory, max degree of parallelism, cost threshold)
- SqlLogin: SA account disabled, Windows auth enforced
- SqlDatabaseRole: separation of duties
- SqlServerAudit: audit spec for login events
- Service: MSSQLSERVER (Running, Automatic)

---

## Summary: File count

| Area | New files |
|---|---|
| Security baselines | 17 (5×3 Windows versions + 1 Edge + 1 M365) |
| STIG 2024 | 10 |
| Citrix | 2 |
| AVD | 2 |
| RDS | 2 |
| Server roles | 6 |
| **Total** | **39** |

---

## Implementation approach

All 6 areas are independent — implement in parallel using separate agents, one agent per area. Each agent receives the naming convention, module version pins, and existing comparable files as reference.

## Verification

After implementation:
- Run `.\helper-scripts\validate-configurations.ps1 -SyntaxOnly` — all new files must pass
- Grep for `DSCFromGPO` and `localhost` node names — must return zero hits in new files
- Confirm each file's Configuration name = Node name = filename (without .ps1)
