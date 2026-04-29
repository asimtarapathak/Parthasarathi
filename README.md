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

## First Run: Readiness Check

When you launch ParthaSarathi for the first time, use the **Readiness Check** option from the main menu. This diagnostic scans your system and reports which artifacts and IR actions are available on your platform. It helps confirm that all necessary tools and permissions are in place before you start collecting artifacts.

<img width="994" height="636" alt="ss1" src="https://github.com/user-attachments/assets/c7998e03-e109-4940-828d-2c0bd02ab8e3" />

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

| Platform | Coverage Summary |
|---|---|
| Windows | Host triage, persistence, scheduled tasks, RDP, Defender, network exposure, browser and file evidence |
| Windows Server | Server inventory, SMB/WinRM, Active Directory context, domain controllers, trusts, privileged groups |
| Linux | System context, processes, users, ports, firewall, services, cron/systemd persistence, shell history, file evidence |
| macOS | System context, processes, users, ports, PF firewall, launchd persistence, privacy-sensitive artifacts, browser evidence |

The detailed artifact lists for each platform are below.

### Windows Artifact Options

| Category | Artifact | Purpose |
|---|---|---|
| Discovery | `processes` | Running processes and command lines |
| Discovery | `services` | Windows services and service state |
| Discovery | `scheduled_tasks` | Scheduled task inventory |
| Discovery | `users` | Local user accounts |
| Discovery | `logged_in_users` | Logged-in users and sessions |
| Discovery | `mounted_filesystems` | Mounted volumes and filesystems |
| Discovery | `system_info_detailed` | Detailed system profile |
| Discovery | `installed_programs` | Installed programs and versions |
| Discovery | `process_tree` | Parent/child process tree |
| Discovery | `listening_ports` | Listening ports and owning processes |
| Persistence | `autoruns_registry` | Registry autoruns |
| Persistence | `registry_autoruns` | Registry Run and RunOnce keys |
| Persistence | `autoruns_startupfolders` | Startup folder items |
| Persistence | `wmi_persistence` | WMI subscription and persistence artifacts |
| Persistence | `shellbags` | ShellBag activity artifacts |
| Persistence | `jumplists` | JumpList activity artifacts |
| Persistence | `lnk_files` | Shortcut and recent activity artifacts |
| Persistence | `ifeo` | Image File Execution Options hooks |
| Persistence | `powershell_history` | PowerShell command history |
| Persistence | `suspicious_autoruns` | Non-standard autorun entries |
| Forensics | `file_details` | File hashes, timestamps, and metadata |
| Forensics | `file_modification_events` | Recent file modification events |
| Forensics | `amcache` | Amcache execution traces |
| Forensics | `shimcache` | ShimCache / AppCompatCache traces |
| Forensics | `windows_eventlog` | Recent System log entries |
| Forensics | `event_logs` | Recent Security log entries |
| Forensics | `powershell_events` | PowerShell operational log events |
| Forensics | `browser_downloads` | Browser download history |
| Forensics | `firefox_addons` | Firefox add-on inventory |
| Forensics | `recycle_bin_files` | Recycle Bin evidence |
| Forensics | `ransomware_suspects` | Double-extension file hunting |
| Network | `process_open_sockets` | Process-to-socket mapping |
| Network | `network_interface` | Network interfaces and addresses |
| Network | `arp_cache` | ARP cache |
| Network | `network_routes` | Network routing table |
| Network | `proxy_settings` | Proxy configuration |
| Network | `hosts_file_dns_info` | Hosts file and DNS cache information |
| Network | `firewall_rules` | Windows firewall rules |
| Network | `network_exposure_windows` | Exposed services, listeners, and firewall profile view |
| Network | `rdp_enabled_check` | RDP status verification |
| Network | `rdp_logs` | RDP-related security events |
| Network | `wlan_profiles` | Wi-Fi profile inventory |
| Network | `usb_devices` | Connected USB devices |
| Network | `usb_deviceclasses` | USB device class registry traces |
| Network | `mounted_devices` | Mounted device registry traces |
| Detection | `dll_hijacking_checks` | Potential DLL hijacking indicators |
| Detection | `process_injection_detection` | Suspicious memory-map or injection checks |
| Detection | `detect_base64_commands` | Encoded command hunting |
| Detection | `detect_suspicious_scheduled_tasks` | Suspicious scheduled tasks |
| Detection | `lsass_handles` | Heuristic LSASS access hunting |
| Detection | `executables_appdata` | Executables staged in user AppData paths |
| Detection | `processes_downloads` | Processes running from Downloads folders |
| Detection | `processes_temp` | Processes running from Temp folders |
| Detection | `defender_status` | Windows Defender / AV posture |

### Windows Server / AD-Focused Options

| Category | Artifact | Purpose |
|---|---|---|
| Server Host | `server_host_context` | Server edition, uptime, and domain role |
| Server Host | `server_installed_roles` | Installed Windows Server roles and features |
| Server Host | `server_local_admins` | Local Administrators membership |
| Server Host | `server_network_exposure` | Server exposure summary |
| Server Host | `server_rdp_sessions` | Active RDP / terminal sessions |
| Remote Mgmt | `server_winrm_config` | WinRM service and listener configuration |
| Remote Mgmt | `server_smb_shares` | SMB shares and share configuration |
| Remote Mgmt | `server_smb_sessions` | Active SMB sessions |
| AD / Directory | `server_ad_critical_services` | AD and infrastructure critical service state |
| AD / Directory | `server_recent_account_changes` | Recent account, group, and security changes |
| AD / Directory | `server_ad_domain_context` | AD domain and forest context |
| AD / Directory | `server_ad_domain_controllers` | Domain controller inventory |
| AD / Directory | `server_ad_privileged_group_members` | Privileged AD group membership |
| AD / Directory | `server_ad_trusts` | AD trust relationships |

### Linux Artifact Options

| Category | Artifact | Purpose |
|---|---|---|
| Discovery | `linux_system_context` | Hostname, kernel, distro, and uptime |
| Discovery | `linux_process_snapshot` | Process snapshot |
| Discovery | `linux_logged_in_users` | Logged-in users and sessions |
| Discovery | `linux_listening_ports` | Listening ports |
| Discovery | `linux_network_connections` | Active network connections |
| Discovery | `linux_services_snapshot` | Services snapshot |
| Discovery | `linux_process_tree` | Process ancestry tree |
| Persistence | `linux_startup_persistence` | Cron/systemd persistence |
| Persistence | `linux_user_startup_persistence` | User startup persistence |
| Persistence | `linux_startup_autoruns` | Enabled services and init scripts |
| Persistence | `linux_shell_history_collection` | Shell history collection |
| Persistence | `linux_login_session_correlation` | Login and session correlation |
| Forensics | `linux_auth_events_recent` | Recent auth events |
| Forensics | `linux_sudoers_and_privilege_paths` | Privilege paths and sudoers entries |
| Forensics | `linux_recent_privilege_events` | Recent privilege events |
| Forensics | `linux_user_accounts_and_group_privileges` | User and group privilege overview |
| Forensics | `linux_recent_executable_writes_execution_correlation` | Write/execute correlation |
| Forensics | `linux_systemd_unit_anomalies` | Suspicious systemd units and overrides |
| Forensics | `linux_world_writable_and_suid_scan` | High-risk world-writable and SUID file scan |
| Forensics | `linux_file_metadata` | File metadata and hashes |
| Network | `linux_firewall_rules_snapshot` | Firewall state and rules |
| Network | `linux_exposed_services` | SSH/Telnet/FTP and risky listeners |
| Network | `linux_network_route_arp_dns` | Route, ARP, and DNS snapshot |
| Network | `linux_dns_cache_and_resolver` | DNS cache and resolver settings |
| Network | `linux_suspicious_network_listeners_by_process` | Listener/process mapping |
| Detection | `linux_kernel_modules` | Loaded kernel modules and suspicious indicators |

### macOS Artifact Options

| Category | Artifact | Purpose |
|---|---|---|
| Discovery | `macos_system_context` | Host, version, kernel, SIP, and uptime |
| Discovery | `macos_process_snapshot` | Process snapshot |
| Discovery | `macos_process_tree_of_pid` | Ancestors and descendants for a chosen PID |
| Discovery | `macos_logged_in_users` | Logged-in users and sessions |
| Discovery | `macos_listening_ports` | Listening ports |
| Discovery | `macos_network_connections` | Active network connections |
| Discovery | `macos_services_snapshot` | launchd services snapshot |
| Discovery | `macos_user_accounts_and_group_privileges` | Users, groups, and admin membership |
| Persistence | `macos_startup_persistence` | LaunchAgents, LaunchDaemons, and Login Items |
| Persistence | `macos_user_startup_persistence` | User startup artifacts |
| Persistence | `macos_launchd_unit_anomalies` | launchd anomalies and unusual plists |
| Persistence | `macos_shell_history_collection` | Shell history collection |
| Persistence | `macos_login_session_correlation` | Login/session correlation |
| Forensics | `macos_auth_events_recent` | Recent auth and security events |
| Forensics | `macos_sudoers_and_privilege_paths` | sudoers and privilege paths |
| Forensics | `macos_recent_privilege_events` | Recent privilege events |
| Forensics | `macos_installed_apps` | Installed apps inventory with hashes |
| Forensics | `macos_quarantine_attributes` | Quarantine attribute findings |
| Forensics | `macos_recently_deleted_files` | Deleted files and Trash artifacts |
| Forensics | `macos_tcc_privacy_permissions` | TCC privacy permissions snapshot |
| Forensics | `macos_gatekeeper_assessment` | Gatekeeper and notarization indicators |
| Forensics | `macos_recent_executable_writes_execution_correlation` | Executable write/exec correlation |
| Forensics | `macos_world_writable_and_suid_scan` | World-writable and SUID scan |
| Forensics | `macos_file_metadata` | File metadata and hashes |
| Network | `macos_firewall_rules_snapshot` | PF and Application Firewall snapshot |
| Network | `macos_exposed_services` | SSH/Telnet/FTP/RDP and risky listeners |
| Network | `macos_network_route_dns` | Route, interface, and DNS snapshot |
| Network | `macos_usb_external_device_timeline` | USB and external device timeline |
| Detection | `macos_kernel_extensions` | Kernel and system extension indicators |

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

### Windows Server IR

- All Windows IR capabilities, plus:
- SMB share enumeration and session handling
- WinRM remote management workflows
- Active Directory user, group, and privilege response actions
- Domain controller and trust monitoring
- Server role and service response actions
- Network isolation and firewall policy enforcement
- AD event log export and forensic review

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

| Platform | Screenshots |
|---|---|
| Windows | <img width="1919" height="1022" alt="win1 3" src="https://github.com/user-attachments/assets/66348760-58d2-4700-a006-318cd5ff04b9" /> |
| Windows Server | <img width="1677" height="874" alt="ws1 3" src="https://github.com/user-attachments/assets/f60ad62b-679d-40e9-86f1-126257e9490f" /> |
| Linux | <img width="1653" height="893" alt="li1 3" src="https://github.com/user-attachments/assets/f01253c4-bbb0-4800-8df1-93515e9631af" /> |
| macOS | <img width="1714" height="1028" alt="mac1 3" src="https://github.com/user-attachments/assets/cfd33b0e-42fe-495c-88e7-c6f1c0057223" /> |

## Notes

- Some Linux service families are distribution dependent and may require additional packages before they can be discovered or toggled.
- For privileged operations, run with sufficient permissions (`sudo` on Linux, elevated shell on Windows, Full Disk Access where required on macOS).
- Artifact availability can vary depending on the host OS version, installed tools, and local privacy settings.
