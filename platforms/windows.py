from dataclasses import dataclass


SPECIAL_ARTIFACTS = [
    ('file_details', 'File details (hashes, timestamps)'),
    ('process_tree', 'Process tree'),
    ('autoruns_registry', 'Autoruns from registry (common keys)'),
    ('autoruns_startupfolders', 'Startup folder items'),
    ('wmi_persistence', 'WMI subscription/persistence artifacts'),
    ('file_modification_events', 'File modification events'),
    ('dll_hijacking_checks', 'DLL hijacking checks'),
    ('process_injection_detection', 'Process injection detection'),
    ('detect_base64_commands', 'Detect base64/encoded commands (PowerShell history)'),
    ('detect_suspicious_scheduled_tasks', 'Suspicious scheduled tasks'),
    ('system_info_detailed', 'Detailed system information'),
    ('rdp_enabled_check', 'Check if RDP is enabled'),
    ('defender_status', 'Windows Defender/Antivirus status'),
    ('recycle_bin_files', 'View deleted files in Recycle Bin'),
    ('hosts_file_dns_info', 'View current DNS cache info'),
    ('network_exposure_windows', 'Windows network exposure (listening ports, firewall profiles, remote services)'),
    ('wlan_profiles', 'WLAN Profiles (All Connected Networks)'),
]

SERVER_SPECIAL_ARTIFACTS = [
    ('server_host_context', 'Windows Server host context (edition, uptime, domain role)'),
    ('server_installed_roles', 'Installed Windows Server roles/features'),
    ('server_smb_shares', 'SMB shares and share configuration'),
    ('server_smb_sessions', 'Active SMB sessions (clients/users)'),
    ('server_ad_critical_services', 'AD/infra critical service status (NTDS, DNS, KDC, Netlogon, DFSR)'),
    ('server_local_admins', 'Local Administrators group membership'),
    ('server_recent_account_changes', 'Recent account/group/security changes (Security log)'),
    ('server_winrm_config', 'WinRM service and listener configuration'),
    ('server_network_exposure', 'Windows Server network exposure (listeners, firewall, critical remote services)'),
    ('server_rdp_sessions', 'Current RDP/terminal sessions'),
    ('server_ad_domain_context', 'AD domain/forest context (read-only)'),
    ('server_ad_domain_controllers', 'AD domain controller inventory (read-only)'),
    ('server_ad_privileged_group_members', 'AD privileged group members (read-only)'),
    ('server_ad_trusts', 'AD trust relationships (read-only)'),
]

SPECIAL_ACTION_KEYS = {k for k, _ in SPECIAL_ARTIFACTS}.union({k for k, _ in SERVER_SPECIAL_ARTIFACTS})


def split_server_artifact_sections(server_options):
    """Return (core_server_artifacts, ad_readonly_artifacts) lists.

    This keeps sectioning logic centralized in the Windows platform module.
    """
    server_core = [(k, d) for k, d in server_options if not k.startswith('server_ad_')]
    server_ad_readonly = [(k, d) for k, d in server_options if k.startswith('server_ad_')]
    return server_core, server_ad_readonly


@dataclass(frozen=True)
class PlatformCatalog:
    special_artifacts: list
    server_special_artifacts: list


def get_catalog() -> PlatformCatalog:
    """Windows catalog provider for CLI artifact menu composition."""
    return PlatformCatalog(
        special_artifacts=SPECIAL_ARTIFACTS,
        server_special_artifacts=SERVER_SPECIAL_ARTIFACTS,
    )
