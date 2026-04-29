from dataclasses import dataclass


SPECIAL_ARTIFACTS = [
    ('macos_system_context', 'macOS system context (host, version, kernel, SIP, uptime)'),
    ('macos_process_snapshot', 'macOS process snapshot'),
    ('macos_process_tree_of_pid', 'macOS process tree for a selected PID (ancestors + descendants)'),
    ('macos_logged_in_users', 'macOS logged-in users and sessions'),
    ('macos_listening_ports', 'macOS listening ports'),
    ('macos_network_connections', 'macOS active network connections'),
    ('macos_firewall_rules_snapshot', 'macOS firewall rules/state (pf + application firewall)'),
    ('macos_exposed_services', 'macOS exposed services (SSH/Telnet/FTP/RDP and risky listeners)'),
    ('macos_services_snapshot', 'macOS launchd services snapshot'),
    ('macos_startup_persistence', 'macOS startup persistence (LaunchAgents/LaunchDaemons/Login Items)'),
    ('macos_auth_events_recent', 'macOS recent auth/security events'),
    ('macos_sudoers_and_privilege_paths', 'macOS sudoers and privilege path indicators'),
    ('macos_user_startup_persistence', 'macOS user startup persistence artifacts'),
    ('macos_recent_privilege_events', 'macOS recent privilege events (sudo/su/auth)'),
    ('macos_kernel_extensions', 'macOS kernel extension/system extension indicators'),
    ('macos_launchd_unit_anomalies', 'macOS launchd unit anomalies and unusual plists'),
    ('macos_network_route_dns', 'macOS route/interface/DNS snapshot'),
    ('macos_user_accounts_and_group_privileges', 'macOS users, groups, and admin membership'),
    ('macos_installed_apps', 'macOS installed apps/programs inventory (with hashes where possible)'),
    ('macos_quarantine_attributes', 'macOS quarantine attribute findings'),
    ('macos_recently_deleted_files', 'macOS recently deleted files (Trash and volume Trashes, best effort)'),
    ('macos_shell_history_collection', 'macOS shell history collection across users'),
    ('macos_tcc_privacy_permissions', 'macOS TCC privacy permissions snapshot (where readable)'),
    ('macos_gatekeeper_assessment', 'macOS Gatekeeper and notarization/security posture indicators'),
    ('macos_usb_external_device_timeline', 'macOS USB/external device connect-disconnect timeline (logs + metadata snapshot)'),
    ('macos_login_session_correlation', 'macOS login/session correlation across who/last/unified logs'),
    ('macos_recent_executable_writes_execution_correlation', 'macOS recent executable writes and execution correlation'),
    ('macos_world_writable_and_suid_scan', 'macOS world-writable and SUID file scan (high risk)'),
    ('macos_file_metadata', 'macOS file metadata and hashes for a chosen file'),
]

SPECIAL_ACTION_KEYS = {k for k, _ in SPECIAL_ARTIFACTS}


@dataclass(frozen=True)
class PlatformCatalog:
    special_artifacts: list
    server_special_artifacts: list


def get_catalog() -> PlatformCatalog:
    """macOS catalog provider for CLI artifact menu composition."""
    return PlatformCatalog(
        special_artifacts=SPECIAL_ARTIFACTS,
        server_special_artifacts=[],
    )
