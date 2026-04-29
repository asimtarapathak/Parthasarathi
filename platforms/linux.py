from dataclasses import dataclass


SPECIAL_ARTIFACTS = [
    ('linux_system_context', 'Linux system context (hostname, kernel, distro, uptime)'),
    ('linux_process_snapshot', 'Linux process snapshot'),
    ('linux_logged_in_users', 'Linux logged-in users/session view'),
    ('linux_listening_ports', 'Linux listening ports'),
    ('linux_network_connections', 'Linux active network connections'),
    ('linux_firewall_rules_snapshot', 'Linux firewall rules snapshot (iptables/nft/ufw/firewalld)'),
    ('linux_exposed_services', 'Linux exposed services (SSH/Telnet/FTP and risky listeners)'),
    ('linux_services_snapshot', 'Linux services snapshot'),
    ('linux_startup_persistence', 'Linux startup/persistence snapshot (cron/systemd)'),
    ('linux_auth_events_recent', 'Linux recent auth events (ssh/sudo/login)'),
    ('linux_sudoers_and_privilege_paths', 'Linux sudoers and privilege paths (NOPASSWD/risky entries)'),
    ('linux_user_startup_persistence', 'Linux user startup persistence (shell profiles, user services, authorized_keys, user crons)'),
    ('linux_recent_privilege_events', 'Linux recent privilege events (sudo/su/auth failures and successes)'),
    ('linux_kernel_modules', 'Linux loaded kernel modules and suspicious indicators'),
    ('linux_startup_autoruns', 'Linux startup autoruns (enabled services, init scripts, rc.local)'),
    ('linux_network_route_arp_dns', 'Linux network route/ARP/DNS resolver snapshot'),
    ('linux_dns_cache_and_resolver', 'Linux DNS cache and resolver configuration snapshot'),
    ('linux_suspicious_network_listeners_by_process', 'Linux suspicious network listeners by process and service'),
    ('linux_user_accounts_and_group_privileges', 'Linux local users, groups, and privilege indicators'),
    ('linux_recent_executable_writes_execution_correlation', 'Linux recent executable writes and execution correlation'),
    ('linux_systemd_unit_anomalies', 'Linux systemd unit anomalies and suspicious overrides'),
    ('linux_login_session_correlation', 'Linux login/session correlation across auth, users, and process context'),
    ('linux_world_writable_and_suid_scan', 'Linux world-writable and SUID file scan (high risk)'),
    ('linux_shell_history_collection', 'Linux shell history collection across local users'),
    ('linux_process_tree', 'Linux process tree / spawn ancestry for a chosen PID'),
    ('linux_file_metadata', 'Linux file metadata and hashes for a chosen file'),
]

SPECIAL_ACTION_KEYS = {k for k, _ in SPECIAL_ARTIFACTS}


@dataclass(frozen=True)
class PlatformCatalog:
    special_artifacts: list
    server_special_artifacts: list


def get_catalog() -> PlatformCatalog:
    """Linux catalog provider for CLI artifact menu composition."""
    return PlatformCatalog(
        special_artifacts=SPECIAL_ARTIFACTS,
        server_special_artifacts=[],
    )
