# ParthaSarathi DFIR & Incident Response Toolkit

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen)
![License](https://img.shields.io/badge/License-See%20repo-lightgrey)

A cross-platform DFIR CLI for artifact collection, browser forensics, and guided incident response supporting Windows, Windows Server, Linux, and macOS with menu-driven workflows.

<img width="2752" height="1536" alt="prototype 1 jpg" src="https://github.com/user-attachments/assets/e4c112b1-d459-4023-8344-b73c0909cb97" />

## Quick Start

1. Download the latest `ParthaSarathi-full-bundle.zip` from the repository's **Releases** page.
2. Extract the ZIP to a local folder.
3. Create and activate a Python virtual environment.
4. Install dependencies and launch the CLI in admin-user mode.

```powershell
# Example: after extracting ParthaSarathi-full-bundle.zip
cd ParthaSarathi

python -m venv .venv
# Windows
.\.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
sudo python parthasarathi.py
```

The release bundle includes the CLI, supporting modules, `platforms/`, and `bin/`, so you can start directly from the extracted folder without cloning the repository.

After downloading the release ZIP, extract it first:

```powershell
# Windows PowerShell
Expand-Archive -Path ParthaSarathi-full-bundle.zip -DestinationPath ParthaSarathi
```

```bash
# Linux / macOS
unzip ParthaSarathi-full-bundle.zip
```

## Overview

This project was built as a practical DFIR tool to demonstrate:

- Cross-platform artifact collection
- Incident response triage and containment
- Browser forensics and evidence preservation
- Structured export of findings for reporting
- Readiness checks and safe execution flows for high-impact actions

The tool is intentionally menu-driven so that it can be used during live triage, lab exercises, and demonstration scenarios without requiring users to remember commands.

## Objectives

- Provide a unified DFIR workflow across Windows, Linux, and macOS
- Reduce manual effort during incident triage and evidence collection
- Normalize output into exportable formats for reporting and analysis
- Offer safe, guided incident response actions with dry-run support where appropriate
- Improve repeatability of investigations through structured menus and readiness checks

## Key Features

- Cross-platform artifact collection
- Guided Incident Response menus for each platform
- Browser artifact collection for major browsers
- CSV, JSON, XLSX, and PDF export support
- Readiness and compatibility checks
- Evidence collection and quarantine-friendly workflows
- Process, network, persistence, and filesystem artifact coverage
- macOS privacy-aware handling for sensitive artifacts such as Safari data

## Tools and Technologies Used

| Category | Technology |
|---|---|
| Language | Python |
| CLI UI | Rich |
| Data handling | pandas |
| Excel export | openpyxl |
| PDF export | reportlab |
| Process utilities | psutil |
| Optional IOC scanning | yara-python |
| Artifact model | osquery-backed queries + native platform collectors |

## Project Structure

```text
ParthaSarathi/
├── parthasarathi.py          # Main CLI, menu logic, platform workflows
├── utils.py                  # osquery runner, command wrapper, export helpers
├── queries.py                # Windows osquery artifact catalog
├── platforms/
│   ├── windows.py            # Windows special artifacts and IR keys
│   ├── linux.py              # Linux special artifacts and IR keys
│   └── macos.py              # macOS special artifacts and IR keys
├── bin/
│   ├── windows/              # Bundled Windows binaries
│   ├── linux/                # Bundled Linux binaries
│   └── macos/                # Bundled macOS binaries
├── outputs/                  # Exported artifact and readiness files
├── collected/                # Collected files during IR actions
└── README.md
```

## Methodology / Investigation Process

ParthaSarathi follows a practical DFIR workflow:

1. **Identify the platform**
   - Detects the runtime OS and loads the correct artifact catalog.

2. **Run readiness checks**
   - Confirms command availability and supported artifact sets before collection.

3. **Collect artifacts**
   - Uses osquery where appropriate.
   - Falls back to native platform collectors for platform-specific or privacy-sensitive sources.

4. **Review findings**
   - Presents results in readable tables.
   - Helps analysts spot suspicious processes, services, persistence, browser activity, and network exposure.

5. **Export evidence**
   - Saves results in analysis-friendly formats for later reporting and validation.

6. **Execute response actions**
   - Offers guided containment and cleanup actions with dry-run support where needed.

## Setup and Installation

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## How to Run

Start the CLI with:

```bash
sudo python parthasarathi.py
```

Then use the interactive menus to choose:

- Artifact collection
- Browser artifacts
- Incident response actions
- Readiness/diagnostic workflows

## Artifact Coverage

### Windows Artifact Options

| Artifact | Purpose |
|---|---|
| `file_details` | File hashes and metadata |
| `process_tree` | Parent/child process tree |
| `autoruns_registry` | Common registry autoruns |
| `autoruns_startupfolders` | Startup folder items |
| `wmi_persistence` | WMI persistence artifacts |
| `file_modification_events` | Recent file modification events |
| `dll_hijacking_checks` | Potential DLL hijacking indicators |
| `process_injection_detection` | Suspicious memory map / injection checks |
| `detect_base64_commands` | Encoded PowerShell command hunting |
| `detect_suspicious_scheduled_tasks` | Suspicious scheduled tasks |
| `system_info_detailed` | System profile details |
| `rdp_enabled_check` | RDP status verification |
| `defender_status` | Windows Defender / AV posture |
| `recycle_bin_files` | Recycle Bin evidence |
| `hosts_file_dns_info` | DNS/hosts information |
| `network_exposure_windows` | Network exposure view |
| `wlan_profiles` | Wi-Fi profile inventory |

### Windows Server / AD-Focused Options

| Artifact | Purpose |
|---|---|
| `server_host_context` | Server edition, uptime, domain role |
| `server_installed_roles` | Installed Windows Server roles/features |
| `server_smb_shares` | SMB shares and configuration |
| `server_smb_sessions` | Active SMB sessions |
| `server_ad_critical_services` | AD-critical service state |
| `server_local_admins` | Local Administrators membership |
| `server_recent_account_changes` | Recent account and group changes |
| `server_winrm_config` | WinRM configuration |
| `server_network_exposure` | Server exposure summary |
| `server_rdp_sessions` | Active RDP/terminal sessions |
| `server_ad_domain_context` | AD domain/forest context |
| `server_ad_domain_controllers` | Domain controller inventory |
| `server_ad_privileged_group_members` | Privileged AD group members |
| `server_ad_trusts` | AD trust relationships |

### Linux Artifact Options

| Artifact | Purpose |
|---|---|
| `linux_system_context` | Hostname, kernel, distro, uptime |
| `linux_process_snapshot` | Process snapshot |
| `linux_logged_in_users` | Logged-in users and sessions |
| `linux_listening_ports` | Listening ports |
| `linux_network_connections` | Active network connections |
| `linux_firewall_rules_snapshot` | Firewall state and rules |
| `linux_exposed_services` | SSH/Telnet/FTP and risky listeners |
| `linux_services_snapshot` | Services snapshot |
| `linux_startup_persistence` | Cron/systemd persistence |
| `linux_auth_events_recent` | Auth events |
| `linux_sudoers_and_privilege_paths` | Privilege paths and sudoers entries |
| `linux_user_startup_persistence` | User startup persistence |
| `linux_recent_privilege_events` | Recent privilege events |
| `linux_kernel_modules` | Kernel modules and indicators |
| `linux_startup_autoruns` | Enabled services and init scripts |
| `linux_network_route_arp_dns` | Route, ARP, DNS snapshot |
| `linux_dns_cache_and_resolver` | DNS cache/resolver settings |
| `linux_suspicious_network_listeners_by_process` | Listener/process mapping |
| `linux_user_accounts_and_group_privileges` | User/group privilege overview |
| `linux_recent_executable_writes_execution_correlation` | Write/execute correlation |
| `linux_systemd_unit_anomalies` | Suspicious systemd units/overrides |
| `linux_login_session_correlation` | Logins and session correlation |
| `linux_world_writable_and_suid_scan` | High-risk file scan |
| `linux_shell_history_collection` | Shell history collection |
| `linux_process_tree` | Process ancestry tree |
| `linux_file_metadata` | File metadata and hashes |

### macOS Artifact Options

| Artifact | Purpose |
|---|---|
| `macos_system_context` | Host, version, kernel, SIP, uptime |
| `macos_process_snapshot` | Process snapshot |
| `macos_process_tree_of_pid` | Ancestors + descendants for a chosen PID |
| `macos_logged_in_users` | Logged-in users and sessions |
| `macos_listening_ports` | Listening ports |
| `macos_network_connections` | Active network connections |
| `macos_firewall_rules_snapshot` | PF + Application Firewall snapshot |
| `macos_exposed_services` | SSH/Telnet/FTP/RDP and risky listeners |
| `macos_services_snapshot` | launchd snapshot |
| `macos_startup_persistence` | LaunchAgents/LaunchDaemons/Login Items |
| `macos_auth_events_recent` | Auth/security events |
| `macos_sudoers_and_privilege_paths` | sudoers and privilege paths |
| `macos_user_startup_persistence` | User startup artifacts |
| `macos_recent_privilege_events` | Privilege events |
| `macos_kernel_extensions` | Kernel/system extension indicators |
| `macos_launchd_unit_anomalies` | launchd anomalies |
| `macos_network_route_dns` | Route/interface/DNS snapshot |
| `macos_user_accounts_and_group_privileges` | Users, groups, admin membership |
| `macos_installed_apps` | Installed apps inventory with hashes |
| `macos_quarantine_attributes` | Quarantine attribute findings |
| `macos_recently_deleted_files` | Deleted files / Trash artifacts |
| `macos_shell_history_collection` | Shell history collection |
| `macos_tcc_privacy_permissions` | TCC privacy permissions snapshot |
| `macos_gatekeeper_assessment` | Gatekeeper/notarization indicators |
| `macos_usb_external_device_timeline` | USB/external device timeline |
| `macos_login_session_correlation` | Login/session correlation |
| `macos_recent_executable_writes_execution_correlation` | Executable write/exec correlation |
| `macos_world_writable_and_suid_scan` | World-writable and SUID scan |
| `macos_file_metadata` | File metadata and hashes |

## Browser Forensics

Supported browser workflows include:

- Browser detection and profile discovery
- History export
- Download history export
- Cookies export
- Extensions inventory
- Extension risk scoring

### Safari Handling

Safari artifacts are handled with macOS privacy constraints in mind.
Where direct database access is blocked, the tool uses fallbacks and shows a clear Full Disk Access guidance message.

## Incident Response Capabilities

### Windows IR

- Process listing and termination
- File collection
- Firewall rule creation/removal
- Service actions
- Event log export
- Registry hive save workflows
- User and persistence response actions
- RDP-related workflows
- Server/AD response options on compatible systems

### Linux IR

- Process actions
- Command execution
- Firewall operations
- SSH/Telnet/FTP/RDP family service controls
- Service stop/remove workflows
- Host isolation and rollback
- User management actions
- Cron cleanup, kill-by-port, quarantine and restore

### macOS IR

- SSH service toggle
- Legacy Telnet/FTP/RDP-like label handling with clear unsupported messaging where appropriate
- PF anchor-based firewall block/unblock
- Host isolation and rollback
- Service stop/remove verification
- User management actions
- Cron cleanup, kill-by-port, quarantine and restore

## Output and Evidence Handling

- Exports are written to `outputs/`
- Collected files are written to `collected/`
- Diagnostic and readiness reports are written to `outputs/` as JSON and CSV

## Sample Output / Screenshots

> Placeholder: will add screenshots soon

| Platform | Screenshot placeholders |
|---|---|
| Windows | Main menu, artifact collection result table, incident response menu, export confirmation screen |
| Windows Server | Artifact menu, Active Directory-focused view, incident response actions, isolation or WinRM workflow |
| Linux | Main menu, artifact collection result table, incident response menu, firewall or host isolation workflow |
| macOS | Main menu, artifact collection result table, incident response menu, Safari or privacy-aware artifact workflow |

## Notes

- Some Linux service families are distribution dependent and may require additional packages before they can be discovered or toggled.
- For privileged operations, run with sufficient permissions (`sudo` on Linux, elevated shell on Windows, Full Disk Access where required on macOS).
- Artifact availability can vary depending on the host OS version, installed tools, and local privacy settings.
