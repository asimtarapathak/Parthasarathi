import os
import sys
import json
import shutil
import subprocess
import hashlib
import shlex
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.markup import escape as rich_escape

from queries import ARTIFACTS
from utils import run_osquery, export_dataframe, json_to_table, run_command, find_procdump
from platforms import detect_platform_runtime
from platforms import windows as windows_platform
from platforms import linux as linux_platform
from platforms import macos as macos_platform
import re
import csv

console = Console()
PLATFORM_RUNTIME = detect_platform_runtime()

if PLATFORM_RUNTIME.os_key in ('windows', 'windows-server'):
    SPECIAL_ARTIFACTS = windows_platform.SPECIAL_ARTIFACTS
    SERVER_SPECIAL_ARTIFACTS = windows_platform.SERVER_SPECIAL_ARTIFACTS
    SPECIAL_ACTION_KEYS = windows_platform.SPECIAL_ACTION_KEYS
elif PLATFORM_RUNTIME.os_key == 'linux':
    SPECIAL_ARTIFACTS = linux_platform.SPECIAL_ARTIFACTS
    SERVER_SPECIAL_ARTIFACTS = []
    SPECIAL_ACTION_KEYS = linux_platform.SPECIAL_ACTION_KEYS
elif PLATFORM_RUNTIME.os_key == 'macos':
    SPECIAL_ARTIFACTS = macos_platform.SPECIAL_ARTIFACTS
    SERVER_SPECIAL_ARTIFACTS = []
    SPECIAL_ACTION_KEYS = macos_platform.SPECIAL_ACTION_KEYS
else:
    SPECIAL_ARTIFACTS = []
    SERVER_SPECIAL_ARTIFACTS = []
    SPECIAL_ACTION_KEYS = set()

if PLATFORM_RUNTIME.os_key == 'macos':
    # Keep key macOS artifact entries visible even if platforms/macos.py in a VM copy is stale.
    _required_macos_artifacts = [
        ('macos_installed_apps', 'macOS installed apps/programs inventory (with hashes where possible)'),
        ('macos_process_tree_of_pid', 'macOS process tree for a selected PID (ancestors + descendants)'),
        ('macos_usb_external_device_timeline', 'macOS USB/external device connect-disconnect timeline (logs + metadata snapshot)'),
    ]
    _existing_keys = {k for k, _ in SPECIAL_ARTIFACTS}
    for _k, _d in _required_macos_artifacts:
        if _k not in _existing_keys:
            SPECIAL_ARTIFACTS.append((_k, _d))
            _existing_keys.add(_k)
    SPECIAL_ACTION_KEYS.update({k for k, _ in _required_macos_artifacts})

# global set of artifacts known to be supported (from last diagnostic)
available_artifacts = set(ARTIFACTS.keys())
available_linux_artifacts = {k for k, _ in linux_platform.SPECIAL_ARTIFACTS}
available_macos_artifacts = {k for k, _ in macos_platform.SPECIAL_ARTIFACTS}

def load_diagnostic():
    global available_artifacts
    path = Path('outputs') / 'osquery_diagnostic.json'
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            available_artifacts = {entry['artifact'] for entry in report if entry.get('available')}
        except Exception:
            available_artifacts = set(ARTIFACTS.keys())
    else:
        available_artifacts = set(ARTIFACTS.keys())


def load_linux_readiness():
    """Load last Linux readiness report and update available Linux artifact set."""
    global available_linux_artifacts
    path = Path('outputs') / 'linux_readiness.json'
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            available_linux_artifacts = {entry['artifact'] for entry in report if entry.get('available')}
            if not available_linux_artifacts:
                available_linux_artifacts = {k for k, _ in linux_platform.SPECIAL_ARTIFACTS}
        except Exception:
            available_linux_artifacts = {k for k, _ in linux_platform.SPECIAL_ARTIFACTS}
    else:
        available_linux_artifacts = {k for k, _ in linux_platform.SPECIAL_ARTIFACTS}


def load_macos_readiness():
    """Load last macOS readiness report and update available macOS artifact set."""
    global available_macos_artifacts
    path = Path('outputs') / 'macos_readiness.json'
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            available_macos_artifacts = {entry['artifact'] for entry in report if entry.get('available')}
            catalog_keys = {k for k, _ in macos_platform.SPECIAL_ARTIFACTS}
            reported_keys = {entry.get('artifact') for entry in report if isinstance(entry, dict)}
            # If readiness file is older than the current catalog, keep new artifact keys visible.
            available_macos_artifacts |= {k for k in catalog_keys if k not in reported_keys}
            if not available_macos_artifacts:
                available_macos_artifacts = {k for k, _ in macos_platform.SPECIAL_ARTIFACTS}
        except Exception:
            available_macos_artifacts = {k for k, _ in macos_platform.SPECIAL_ARTIFACTS}
    else:
        available_macos_artifacts = {k for k, _ in macos_platform.SPECIAL_ARTIFACTS}


def _linux_has_command(cmd):
    res = run_command(f'command -v {cmd} >/dev/null 2>&1 && echo yes || echo no', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        return res[0]['_output'].strip().lower() == 'yes'
    return False


def _linux_is_root():
    res = run_command('id -u', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        return res[0]['_output'].strip() == '0'
    return False


def _linux_has_sudo_non_interactive():
    res = run_command('sudo -n true >/dev/null 2>&1 && echo yes || echo no', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        return res[0]['_output'].strip().lower() == 'yes'
    return False


def _linux_file_exists(path):
    res = run_command(f'test -e {shlex.quote(path)} && echo yes || echo no', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        return res[0]['_output'].strip().lower() == 'yes'
    return False


def linux_readiness_report():
    """Run Linux capability diagnostic and persist readiness report."""
    console.print('\nRunning Linux capability readiness check...')
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)

    requirements = {
        'linux_system_context': [['hostname'], ['uname'], ['uptime']],
        'linux_process_snapshot': [['ps']],
        'linux_logged_in_users': [['who', 'w']],
        'linux_listening_ports': [['ss', 'netstat']],
        'linux_network_connections': [['ss', 'netstat']],
        'linux_firewall_rules_snapshot': [['iptables', 'nft', 'ufw', 'firewall-cmd']],
        'linux_exposed_services': [['ss', 'netstat']],
        'linux_services_snapshot': [['systemctl', 'service']],
        'linux_startup_persistence': [['crontab', 'systemctl', 'ls']],
        'linux_auth_events_recent': [['tail', 'journalctl']],
        'linux_sudoers_and_privilege_paths': [['cat', 'ls']],
        'linux_user_startup_persistence': [['cat', 'ls']],
        'linux_recent_privilege_events': [['tail', 'journalctl']],
        'linux_kernel_modules': [['lsmod']],
        'linux_startup_autoruns': [['systemctl', 'service', 'ls']],
        'linux_network_route_arp_dns': [['ip', 'arp', 'cat']],
        'linux_dns_cache_and_resolver': [['cat', 'resolvectl', 'systemd-resolve', 'nmcli']],
        'linux_suspicious_network_listeners_by_process': [['ss', 'netstat', 'ps']],
        'linux_user_accounts_and_group_privileges': [['getent', 'id', 'groups', 'cut']],
        'linux_recent_executable_writes_execution_correlation': [['find', 'stat', 'ps']],
        'linux_systemd_unit_anomalies': [['systemctl', 'ls', 'grep']],
        'linux_login_session_correlation': [['who', 'last', 'journalctl']],
        'linux_world_writable_and_suid_scan': [['find']],
        'linux_shell_history_collection': [['cat', 'ls']],
        'linux_process_tree': [['ps']],
        'linux_file_metadata': [['python3', 'python']],
    }

    ir_requirements = {
        'linux_ir_firewall_block': [['iptables', 'nft']],
        'linux_ir_service_control': [['systemctl', 'service']],
        'linux_ir_ssh_toggle': [['systemctl', 'service']],
        'linux_ir_telnet_toggle': [['systemctl', 'service']],
        'linux_ir_ftp_toggle': [['systemctl', 'service']],
        'linux_ir_safe_isolation': [['iptables', 'nft', 'ufw', 'firewall-cmd']],
        'linux_ir_firewall_rules_list': [['iptables', 'nft', 'ufw', 'firewall-cmd']],
        'linux_ir_user_lock': [['usermod', 'chage', 'useradd', 'userdel', 'gpasswd', 'deluser']],
        'linux_ir_cron_cleanup': [['crontab']],
        'linux_ir_kill_by_port': [['ss', 'netstat'], ['kill']],
        'linux_ir_quarantine_file': [['mv', 'cp', 'sha256sum']],
        'linux_ir_quarantine_restore': [['mv', 'ls', 'cat', 'test']],
    }

    root_mode = _linux_is_root()
    sudo_mode = _linux_has_sudo_non_interactive()
    report = []

    # Environment capability rows (in addition to artifact/action checks)
    service_mgrs = [c for c in ('systemctl', 'service') if _linux_has_command(c)]
    fw_backends = [c for c in ('iptables', 'nft', 'ufw', 'firewall-cmd') if _linux_has_command(c)]
    log_sources = []
    if _linux_file_exists('/var/log/auth.log'):
        log_sources.append('/var/log/auth.log')
    if _linux_file_exists('/var/log/secure'):
        log_sources.append('/var/log/secure')
    if _linux_has_command('journalctl'):
        log_sources.append('journalctl')

    report.append({
        'artifact': 'linux_cap_service_manager',
        'available': bool(service_mgrs),
        'present_commands': service_mgrs,
        'missing_commands': [c for c in ('systemctl', 'service') if c not in service_mgrs],
        'notes': 'No Linux service manager detected' if not service_mgrs else '',
    })
    report.append({
        'artifact': 'linux_cap_firewall_backend',
        'available': bool(fw_backends),
        'present_commands': fw_backends,
        'missing_commands': [c for c in ('iptables', 'nft', 'ufw', 'firewall-cmd') if c not in fw_backends],
        'notes': 'No supported firewall backend detected' if not fw_backends else '',
    })
    report.append({
        'artifact': 'linux_cap_log_sources',
        'available': bool(log_sources),
        'present_commands': log_sources,
        'missing_commands': [],
        'notes': 'No standard auth log source available' if not log_sources else '',
    })
    report.append({
        'artifact': 'linux_cap_privilege_level',
        'available': root_mode or sudo_mode,
        'present_commands': ['root'] if root_mode else (['sudo-nopasswd'] if sudo_mode else []),
        'missing_commands': [],
        'notes': 'High-impact actions may be blocked without root/sudo' if not (root_mode or sudo_mode) else '',
    })

    for key, groups in requirements.items():
        commands = sorted({cmd for group in groups for cmd in group})
        present = [c for c in commands if _linux_has_command(c)]
        missing = [c for c in commands if c not in present]
        available = all(any(c in present for c in group) for group in groups)

        notes = []
        if key in (
            'linux_auth_events_recent',
            'linux_startup_persistence',
            'linux_services_snapshot',
            'linux_exposed_services',
            'linux_sudoers_and_privilege_paths',
            'linux_user_startup_persistence',
            'linux_recent_privilege_events',
            'linux_world_writable_and_suid_scan',
            'linux_shell_history_collection',
        ) and not root_mode:
            notes.append('May require sudo/root for complete data')
        if key in ('linux_listening_ports', 'linux_network_connections') and 'ss' not in present and 'netstat' not in present:
            notes.append('Install iproute2 (ss) or net-tools (netstat)')
        if key == 'linux_exposed_services' and not (_linux_has_command('systemctl') or _linux_has_command('service')):
            notes.append('Service state enrichment unavailable (systemctl/service missing)')

        report.append({
            'artifact': key,
            'available': available,
            'present_commands': present,
            'missing_commands': missing,
            'notes': '; '.join(notes),
        })

    for key, groups in ir_requirements.items():
        commands = sorted({cmd for group in groups for cmd in group})
        present = [c for c in commands if _linux_has_command(c)]
        missing = [c for c in commands if c not in present]
        available = all(any(c in present for c in group) for group in groups)
        notes = []
        if not root_mode:
            if sudo_mode:
                notes.append('Partial: sudo available, but tool currently runs direct commands')
            else:
                notes.append('Blocked: requires root/sudo privileges')
        else:
            notes.append('Full: root privileges detected')
        report.append({
            'artifact': key,
            'available': available,
            'present_commands': present,
            'missing_commands': missing,
            'notes': '; '.join(notes),
        })

    out_json = outdir / 'linux_readiness.json'
    out_csv = outdir / 'linux_readiness.csv'

    with out_json.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    with out_csv.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['artifact', 'available', 'present_commands', 'missing_commands', 'notes'])
        for r in report:
            writer.writerow([
                r.get('artifact', ''),
                r.get('available', False),
                ';'.join(r.get('present_commands', [])),
                ';'.join(r.get('missing_commands', [])),
                r.get('notes', ''),
            ])

    global available_linux_artifacts
    artifact_keys = {k for k, _ in linux_platform.SPECIAL_ARTIFACTS}
    available_linux_artifacts = {
        entry['artifact'] for entry in report
        if entry.get('available') and entry.get('artifact') in artifact_keys
    }

    supported = sorted(available_linux_artifacts)
    unsupported = sorted([entry['artifact'] for entry in report if not entry.get('available')])

    console.print('\n[bold]Linux Readiness Summary[/bold]')
    console.print(f'Supported Linux capabilities: {len(supported)}')
    console.print(f'Unsupported Linux capabilities: {len(unsupported)}')
    if unsupported:
        console.print('[yellow]' + ', '.join(unsupported) + '[/yellow]')
    console.print(f'Linux readiness saved: {out_json} and {out_csv}')
    return report


def macos_readiness_report():
    """Run macOS capability diagnostic and persist readiness report."""
    console.print('\nRunning macOS capability readiness check...')
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)

    requirements = {
        'macos_system_context': [['hostname'], ['sw_vers', 'uname']],
        'macos_process_snapshot': [['ps']],
        'macos_process_tree_of_pid': [['ps']],
        'macos_logged_in_users': [['who', 'w']],
        'macos_listening_ports': [['lsof', 'netstat']],
        'macos_network_connections': [['netstat']],
        'macos_firewall_rules_snapshot': [['pfctl', 'socketfilterfw']],
        'macos_exposed_services': [['lsof', 'netstat', 'launchctl']],
        'macos_services_snapshot': [['launchctl']],
        'macos_startup_persistence': [['find', 'ls']],
        'macos_auth_events_recent': [['log']],
        'macos_sudoers_and_privilege_paths': [['cat', 'grep']],
        'macos_user_startup_persistence': [['ls', 'cat']],
        'macos_recent_privilege_events': [['log']],
        'macos_kernel_extensions': [['kextstat', 'kmutil', 'systemextensionsctl']],
        'macos_launchd_unit_anomalies': [['launchctl', 'ls']],
        'macos_network_route_dns': [['route', 'ifconfig', 'scutil']],
        'macos_user_accounts_and_group_privileges': [['dscl', 'id', 'dscacheutil']],
        'macos_installed_apps': [['python3', 'python']],
        'macos_quarantine_attributes': [['xattr', 'find']],
        'macos_recently_deleted_files': [['find', 'ls', 'stat']],
        'macos_shell_history_collection': [['cat', 'ls']],
        'macos_tcc_privacy_permissions': [['sqlite3', 'ls']],
        'macos_gatekeeper_assessment': [['spctl', 'defaults']],
        'macos_usb_external_device_timeline': [['log'], ['system_profiler', 'ioreg', 'diskutil']],
        'macos_login_session_correlation': [['who', 'last', 'log']],
        'macos_recent_executable_writes_execution_correlation': [['find', 'log']],
        'macos_world_writable_and_suid_scan': [['find']],
        'macos_file_metadata': [['python3', 'python']],
    }

    report = []
    for key, groups in requirements.items():
        commands = sorted({cmd for group in groups for cmd in group})
        present = [c for c in commands if _linux_has_command(c)]
        missing = [c for c in commands if c not in present]
        available = all(any(c in present for c in group) for group in groups)

        notes = []
        if key in ('macos_firewall_rules_snapshot', 'macos_exposed_services', 'macos_auth_events_recent', 'macos_usb_external_device_timeline') and not _linux_is_root():
            notes.append('May require sudo/root for complete data')

        report.append({
            'artifact': key,
            'available': available,
            'present_commands': present,
            'missing_commands': missing,
            'notes': '; '.join(notes),
        })

    out_json = outdir / 'macos_readiness.json'
    out_csv = outdir / 'macos_readiness.csv'

    with out_json.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    with out_csv.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['artifact', 'available', 'present_commands', 'missing_commands', 'notes'])
        for r in report:
            writer.writerow([
                r.get('artifact', ''),
                r.get('available', False),
                ';'.join(r.get('present_commands', [])),
                ';'.join(r.get('missing_commands', [])),
                r.get('notes', ''),
            ])

    global available_macos_artifacts
    artifact_keys = {k for k, _ in macos_platform.SPECIAL_ARTIFACTS}
    available_macos_artifacts = {
        entry['artifact'] for entry in report
        if entry.get('available') and entry.get('artifact') in artifact_keys
    }

    supported = sorted(available_macos_artifacts)
    unsupported = sorted([entry['artifact'] for entry in report if not entry.get('available')])

    console.print('\n[bold]macOS Readiness Summary[/bold]')
    console.print(f'Supported macOS capabilities: {len(supported)}')
    console.print(f'Unsupported macOS capabilities: {len(unsupported)}')
    if unsupported:
        console.print('[yellow]' + ', '.join(unsupported) + '[/yellow]')
    console.print(f'macOS readiness saved: {out_json} and {out_csv}')
    return report

# load on import
load_diagnostic()
load_linux_readiness()
load_macos_readiness()


def choose_artifact():
    console.print("\nAvailable artifacts (auto-pruned by last diagnostic):\n")
    visible = []
    linux_special_visible = SPECIAL_ARTIFACTS
    if PLATFORM_RUNTIME.os_key in ('windows', 'windows-server'):
        load_diagnostic()
        hidden_from_windows_artifacts = {'firefox_addons'}
        visible = [
            (k, ARTIFACTS[k]['desc'])
            for k in ARTIFACTS
            if k in available_artifacts and k not in hidden_from_windows_artifacts
        ]
    elif PLATFORM_RUNTIME.os_key == 'linux':
        load_linux_readiness()
        linux_special_visible = [(k, d) for k, d in SPECIAL_ARTIFACTS if k in available_linux_artifacts]
    elif PLATFORM_RUNTIME.os_key == 'macos':
        load_macos_readiness()
        # macOS artifact collectors are Python/native helpers; always show the full catalog so stale
        # readiness reports do not hide newly added items.
        linux_special_visible = list(SPECIAL_ARTIFACTS)

    common_options = visible + linux_special_visible
    server_mode = PLATFORM_RUNTIME.is_server
    server_options = SERVER_SPECIAL_ARTIFACTS if server_mode else []

    options = common_options + server_options

    if not options:
        console.print('[yellow]No supported artifacts detected; run diagnostic/readiness check first[/yellow]')
        return []

    indexed_options = []
    if server_mode:
        console.print('[dim]------------------------------------------------------------[/dim]')
        console.print('[dim]Legend: Windows Server only sections are unavailable on desktop Windows.[/dim]')
        console.print('[dim]------------------------------------------------------------[/dim]')
        console.print('[bold cyan]Windows (Common) Artifacts[/bold cyan]')
        for key, desc in common_options:
            indexed_options.append((key, desc))
            console.print(f"{len(indexed_options)}. {key} - {desc}")

        server_core, server_ad_readonly = windows_platform.split_server_artifact_sections(server_options)

        console.print('\n[bold magenta]Windows Server Only Artifacts[/bold magenta]')
        for key, desc in server_core:
            indexed_options.append((key, desc))
            console.print(f"{len(indexed_options)}. {key} - {desc}")

        console.print('\n[bold green]Active Directory Focused (Read-Only) Artifacts[/bold green]')
        for key, desc in server_ad_readonly:
            indexed_options.append((key, desc))
            console.print(f"{len(indexed_options)}. {key} - {desc}")
    else:
        for key, desc in options:
            indexed_options.append((key, desc))
            console.print(f"{len(indexed_options)}. {key} - {desc}")

    back_idx = len(indexed_options) + 1
    console.print(f"{back_idx}. back - Go back to previous menu")

    choice = console.input('\nEnter numbers (comma-separated), "all", or back option number: ')
    if choice.strip().lower() in ('back', 'b', str(back_idx)):
        return None
    if choice.strip().lower() == 'all':
        return [k for k, _ in indexed_options]

    picks = []
    for token in choice.split(','):
        token = token.strip()
        if not token:
            continue
        try:
            idx = int(token) - 1
            if 0 <= idx < len(indexed_options):
                picks.append(indexed_options[idx][0])
        except Exception:
            if token in ARTIFACTS or any(token == k for k, _ in SPECIAL_ARTIFACTS) or any(token == k for k, _ in SERVER_SPECIAL_ARTIFACTS):
                picks.append(token)
    return picks


def display_and_export(name, data):
    if not data:
        console.print('[yellow]No rows returned.[/yellow]')
        return
    # If osquery returned structured error, display it clearly
    first = data[0]
    if isinstance(first, dict) and ('_error' in first or '_output' in first):
        if '_error' in first:
            console.print(f"[red]osquery error: {first['_error']}[/red]")
        elif '_output' in first:
            console.print('[green]Raw output:[/green]')
            console.print(first['_output'])
        return

    # Add hashes for installed programs when possible (makes exports more useful)
    if name in ('installed_programs_hashes',):
        try:
            import os, hashlib
            for row in data:
                if isinstance(row, dict):
                    loc = row.get('install_location') or row.get('install_path') or row.get('path')
                    if loc and os.path.isfile(loc):
                        try:
                            with open(loc, 'rb') as f:
                                row['sha256'] = hashlib.sha256(f.read()).hexdigest()
                        except Exception:
                            row['sha256'] = 'N/A'
                    else:
                        row['sha256'] = 'N/A'
        except Exception:
            pass

    # Preview only first N rows to avoid huge dumps
    preview = console.input('Rows to preview (default 20, enter 0 for all): ')
    try:
        n = int(preview)
    except Exception:
        n = 20
    if n == 0:
        table = json_to_table(data)
    else:
        table = json_to_table(data[:n])
    console.print(table)

    console.print('\nExport options:')
    console.print('1. CSV  2. JSON  3. XLSX  4. PDF  5. Skip')
    choice = console.input('Choose export format (1-5): ')
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = outdir / f"{name}_{ts}"
    if choice == '1':
        export_dataframe(data, fname.with_suffix('.csv'))
        console.print(f"Saved {fname.with_suffix('.csv')}")
    elif choice == '2':
        export_dataframe(data, fname.with_suffix('.json'))
        console.print(f"Saved {fname.with_suffix('.json')}")
    elif choice == '3':
        export_dataframe(data, fname.with_suffix('.xlsx'))
        console.print(f"Saved {fname.with_suffix('.xlsx')}")
    elif choice == '4':
        export_dataframe(data, fname.with_suffix('.pdf'))
        console.print(f"Saved {fname.with_suffix('.pdf')}")
    else:
        console.print('Skipping export')


def artifact_collection_menu():
    """Looping menu for artifact collection."""
    while True:
        console.print('\nArtifact Collection:')
        console.print('1. Run predefined artifacts  2. Run raw SQL  3. Back to main menu')
        sub = console.input('Choose (1-3): ').strip()
        
        if sub == '1':
            run_predefined_artifacts_loop()
        elif sub == '2':
            sql = console.input('Enter raw SQL to run: ')
            console.rule('Raw SQL')
            try:
                data = run_osquery(sql)
                display_and_export('raw_sql', data)
            except Exception as e:
                console.print(f'[red]osquery error: {e}[/red]')
        elif sub == '3':
            break
        else:
            console.print('[yellow]Invalid choice.[/yellow]')


def run_predefined_artifacts_loop():
    """Looping submenu for running predefined artifacts."""
    while True:
        picks = choose_artifact()
        if picks is None:
            break
        if picks:
            run_artifact_batch(picks)


def run_artifact_batch(names):
    from collections import OrderedDict
    results = OrderedDict()

    for name in names:
        console.rule(f'Artifact: {name}')
        # handle special actions (non-osquery)
        if (name in SPECIAL_ACTION_KEYS or name.startswith('macos_')) and name in globals() and callable(globals()[name]):
            try:
                globals()[name]()
            except Exception as e:
                console.print(f'[red]Error running {name}: {rich_escape(str(e))}[/red]')
            continue

        data = try_run_artifact(name)
        # Recycle Bin often returns no rows in osquery depending on permissions/build;
        # fall back to direct filesystem collector for better reliability.
        if name == 'recycle_bin' and (not data or (isinstance(data, list) and data and isinstance(data[0], dict) and '_error' in data[0])):
            console.print('[yellow]No usable rows from osquery recycle_bin; falling back to direct Recycle Bin scan.[/yellow]')
            try:
                recycle_bin_files()
            except Exception as e:
                console.print(f'[red]Recycle Bin fallback failed: {e}[/red]')
            continue
        # if table-level missing message, present a friendly note
        if isinstance(data, list) and data and isinstance(data[0], dict) and '_error' in data[0]:
            err = data[0]['_error']
            if 'no such table' in err.lower():
                console.print(f"[yellow]Artifact '{name}' not available in this osquery build: {err}[/yellow]")
                continue
        results[name] = data
        display_and_export(name, data)
    # offer combined export
    if results:
        choice = console.input('Save combined results to XLSX with separate sheets? (y/N): ')
        if choice.strip().lower() == 'y':
            try:
                import pandas as pd
                outdir = Path('outputs')
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                outpath = outdir / f'combined_artifacts_{ts}.xlsx'
                with pd.ExcelWriter(outpath) as writer:
                    for sheet, rows in results.items():
                        pd.DataFrame(rows).to_excel(writer, sheet_name=sheet[:31], index=False)
                console.print(f'Saved {outpath}')
            except Exception as e:
                console.print(f'[red]Combined export failed: {rich_escape(str(e))}[/red]')


def get_firewall_rules():
    """Get list of firewall rules with name, direction, remoteip."""
    res = run_command('netsh advfirewall firewall show rule name=all', shell=True)
    rules = []
    if res and isinstance(res, list) and '_output' in res[0]:
        output = res[0]['_output']
        lines = output.split('\n')
        current_rule = {}
        for line in lines:
            line = line.strip()
            if line.startswith('Rule Name:'):
                if current_rule:
                    rules.append(current_rule)
                current_rule = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('Direction:'):
                current_rule['direction'] = line.split(':', 1)[1].strip().lower()
            elif line.startswith('RemoteIP:'):
                current_rule['remoteip'] = line.split(':', 1)[1].strip()
        if current_rule:
            rules.append(current_rule)
    return rules

def check_existing_rules_for_ip(ip):
    """Return list of rules that match the IP."""
    rules = get_firewall_rules()
    matching = []
    for rule in rules:
        remoteip = rule.get('remoteip', '')
        if ip in remoteip or remoteip == ip:
            matching.append(rule)
    return matching


def _print_ir_dry_run(action, details=None, commands=None):
    """Print a consistent dry-run preview for high-impact IR actions."""
    console.print('[cyan]DRY-RUN MODE: no changes were applied.[/cyan]')
    console.print(f'Action: {action}')
    if details:
        for k, v in details.items():
            console.print(f'  {k}: {v}')
    if commands:
        console.print('Commands that would run:')
        for c in commands:
            console.print(f'  - {c}')


def incident_response_menu():
    ir_dry_run = console.input('Enable dry-run for all high-impact actions this IR session? (y/N): ').strip().lower() == 'y'
    if ir_dry_run:
        console.print('[cyan]Dry-run is ON for this IR session.[/cyan]')

    while True:
        server_mode = PLATFORM_RUNTIME.is_server
        console.print('\n[bold yellow]Incident Response Actions:[/bold yellow]')
        if server_mode:
            console.print('[dim]------------------------------------------------------------[/dim]')
            console.print('[dim]Server-only actions may require Domain Admin / local admin rights.[/dim]')
            console.print('[dim]------------------------------------------------------------[/dim]')
            console.print('[bold cyan]Windows (Common) IR Actions[/bold cyan]')
        console.print('1.  List processes')
        console.print('2.  Kill process by PID')
        console.print('3.  Collect file (copy to ./collected)')
        console.print('4.  Run command')
        console.print('5.  Block IP')
        console.print('6.  Unblock IP')
        console.print('7.  List firewall rules')
        console.print('8.  Stop service')
        console.print('9.  Export Event Log')
        console.print('10. Save Registry Hive')
        console.print('11. Netstat snapshot')
        console.print('12. User management')
        console.print('13. Delete file')
        console.print('14. Remove persistence')
        console.print('15. Suspend process')
        console.print('16. Disable RDP')
        console.print('17. Enable RDP')
        console.print('18. Enable Antivirus/Defender')
        console.print('19. Disable Antivirus/Defender')
        if server_mode:
            console.print('\n[bold magenta]Windows Server Only IR Actions[/bold magenta]')
            console.print('20. List SMB sessions')
            console.print('21. Close SMB session by SessionId')
            console.print('22. Disable WinRM')
            console.print('23. Enable WinRM')
            console.print('24. Emergency network isolation (block all in/out firewall)')
            console.print('25. Roll back isolation policy (block inbound, allow outbound)')
            console.print('26. Disable user account')
            console.print('27. Disable scheduled task by name')
            console.print('28. Log off terminal session by Session ID')
            console.print('\n[bold green]Active Directory Optional Response Actions[/bold green]')
            console.print('29. Remove user from privileged AD group')
            console.print('30. Disable AD computer account')
            console.print('31. Back to main menu')
            choice = console.input('Choose action (1-31): ').strip()
        else:
            console.print('20. Back to main menu')
            choice = console.input('Choose action (1-20): ').strip()

        if choice == '1':
            data = run_osquery('processes')
            if data and isinstance(data, list) and data and '_error' in data[0]:
                console.print(f"[red]osquery error: {data[0]['_error']}[/red]")
            else:
                display_and_export('processes_ir', data)
        elif choice == '2':
            pid = console.input('PID to kill: ').strip()
            if not pid.isdigit():
                console.print('[red]Invalid PID[/red]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Kill process by PID', details={'PID': pid}, commands=[f'Terminate process PID {pid}'])
                continue
            try:
                import psutil
                p = psutil.Process(int(pid))
                pname = p.name()
                p.terminate()
                console.print(f'Terminated {pname} (PID {pid})')
            except psutil.NoSuchProcess:
                console.print(f'[yellow]No process with PID {pid}[/yellow]')
            except Exception as e:
                console.print(f'[red]Failed to kill process: {e}[/red]')
        elif choice == '3':
            path = console.input('Full file path to collect: ').strip()
            if not path:
                console.print('[red]No path provided[/red]')
                continue
            outdir = Path('collected')
            outdir.mkdir(exist_ok=True)
            try:
                dst = outdir / Path(path).name
                shutil.copy2(path, dst)
                console.print(f'Collected file to {dst}')
            except Exception as e:
                console.print(f'[red]Collect failed: {e}[/red]')
        elif choice == '4':
            cmd = console.input('Command to run: ').strip()
            if not cmd:
                console.print('[yellow]No command entered, skipping.[/yellow]')
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Command failed: {res[0]['_error']}[/red]")
            else:
                console.print(res[0].get('_output', ''))
        elif choice == '5':
            ip = console.input('IP address to block: ').strip()
            if not ip:
                console.print('[red]No IP entered[/red]')
                continue
            # Check existing rules
            existing = check_existing_rules_for_ip(ip)
            if existing:
                console.print(f'Existing rules for {ip}:')
                for rule in existing:
                    console.print(f'  - {rule["name"]} ({rule.get("direction", "unknown")})')
                console.print('[yellow]IP already has rules. Skipping creation.[/yellow]')
                continue
            # Choose direction
            console.print('Block direction: 1. Inbound  2. Outbound  3. Both')
            dir_choice = console.input('Choose (1-3): ').strip()
            if dir_choice == '1':
                directions = ['in']
            elif dir_choice == '2':
                directions = ['out']
            elif dir_choice == '3':
                directions = ['in', 'out']
            else:
                console.print('[yellow]Invalid choice[/yellow]')
                continue
            # Rule name
            default_name = f'Block {ip}'
            name = console.input(f'Rule name (default: {default_name}): ').strip() or default_name
            # Confirm
            confirm = console.input(f'Create rule "{name}" for {ip} ({", ".join(directions)})? (y/N): ').strip().lower()
            if confirm != 'y':
                console.print('Cancelled.')
                continue
            if ir_dry_run:
                cmds = [f'netsh advfirewall firewall add rule name="{name}" dir={d} action=block remoteip={ip}' for d in directions]
                _print_ir_dry_run('Block IP via firewall rule', details={'IP': ip, 'Rule Name': name, 'Directions': ', '.join(directions)}, commands=cmds)
                continue
            # Create rules
            for dir in directions:
                cmd = f'netsh advfirewall firewall add rule name="{name}" dir={dir} action=block remoteip={ip}'
                res = run_command(cmd, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    console.print(f"[red]Failed to add {dir} rule: {res[0]['_error']}[/red]")
                else:
                    console.print(f'Added {dir}bound rule: {name}')
        elif choice == '6':
            ip = console.input('IP address to unblock: ').strip()
            if not ip:
                console.print('[red]No IP entered[/red]')
                continue
            existing = check_existing_rules_for_ip(ip)
            if not existing:
                console.print(f'[yellow]No rules found for {ip}[/yellow]')
                continue
            console.print(f'Existing rules for {ip}:')
            for i, rule in enumerate(existing, 1):
                console.print(f'{i}. {rule["name"]} ({rule.get("direction", "unknown")})')
            choice_num = console.input('Enter number to remove (or "all"): ').strip()
            if choice_num.lower() == 'all':
                to_remove = existing
            else:
                try:
                    idx = int(choice_num) - 1
                    if 0 <= idx < len(existing):
                        to_remove = [existing[idx]]
                    else:
                        console.print('[yellow]Invalid number[/yellow]')
                        continue
                except ValueError:
                    console.print('[yellow]Invalid input[/yellow]')
                    continue
            confirm = console.input(f'Remove {len(to_remove)} rule(s)? (y/N): ').strip().lower()
            if confirm != 'y':
                console.print('Cancelled.')
                continue
            if ir_dry_run:
                cmds = [f'netsh advfirewall firewall delete rule name="{rule["name"]}"' for rule in to_remove]
                _print_ir_dry_run('Unblock IP by removing firewall rules', details={'IP': ip, 'Rules': len(to_remove)}, commands=cmds)
                continue
            for rule in to_remove:
                cmd = f'netsh advfirewall firewall delete rule name="{rule["name"]}"'
                res = run_command(cmd, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    console.print(f"[red]Failed to remove {rule['name']}: {res[0]['_error']}[/red]")
                else:
                    console.print(f'Removed rule: {rule["name"]}')
        elif choice == '7':
            rules = get_firewall_rules()
            if not rules:
                console.print('No firewall rules found.')
            else:
                console.print('Firewall rules:')
                for rule in rules:
                    console.print(f'  {rule["name"]} - {rule.get("direction", "unknown")} - {rule.get("remoteip", "any")}')
        elif choice == '8':
            svc = console.input('Service name to stop: ').strip()
            if not svc:
                console.print('[red]No service name entered[/red]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Stop service', details={'Service': svc}, commands=[f'sc stop "{svc}"'])
                continue
            res = run_command(f'sc stop "{svc}"', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to stop service: {res[0]['_error']}[/red]")
            else:
                console.print(f'Stopped service {svc}')
        elif choice == '9':
            # export System event log (example)
            outdir = Path('collected')
            outdir.mkdir(exist_ok=True)
            out = outdir / 'System.evtx'
            res = run_command(f'wevtutil epl System "{out}"', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]wevtutil failed: {res[0]['_error']}[/red]")
            else:
                console.print(f'Exported System event log to {out}')
        elif choice == '10':
            # Save registry hive (requires admin)
            hive = console.input('Hive to save (HKLM\\SYSTEM or HKLM\\SOFTWARE): ').strip()
            if not hive:
                console.print('[red]No hive specified[/red]')
                continue
            outdir = Path('collected')
            outdir.mkdir(exist_ok=True)
            filename = outdir / (hive.replace('\\', '_').replace(':', '') + '.hiv')
            cmd = f'reg save "{hive}" "{filename}" /y'
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]reg save failed: {res[0]['_error']}[/red]")
            else:
                console.print(f'Saved hive to {filename}')
        elif choice == '11':
            res = run_command('netstat -ano', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]netstat failed: {res[0]['_error']}[/red]")
            else:
                outdir = Path('outputs')
                outdir.mkdir(exist_ok=True)
                ts = Path(f"netstat_{Path.cwd().name}_{os.getpid()}.txt")
                p = outdir / ts
                p.write_text(res[0].get('_output', ''))
                console.print(f'Saved netstat snapshot to {p}')
        elif choice == '12':
            user_management(ir_dry_run=ir_dry_run)
        elif choice == '13':
            path = console.input('File path to delete: ').strip()
            if ir_dry_run:
                _print_ir_dry_run('Delete file', details={'Path': path}, commands=[f'Delete file at {path}'])
                continue
            if os.path.exists(path):
                os.remove(path)
                console.print(f'Deleted {path}')
            else:
                console.print('File not found')
        elif choice == '14':
            if ir_dry_run:
                _print_ir_dry_run('Remove persistence', details={'Mode': 'interactive'}, commands=['User-selected persistence removal actions'])
                continue
            remove_persistence()
        elif choice == '15':
            pid = console.input('PID to suspend: ').strip()
            if ir_dry_run:
                _print_ir_dry_run('Suspend process', details={'PID': pid}, commands=[f'Suspend process PID {pid}'])
                continue
            try:
                import psutil
                p = psutil.Process(int(pid))
                p.suspend()
                console.print(f'Process {pid} suspended')
            except Exception as e:
                console.print(f'[red]Failed: {e}[/red]')
        elif choice == '16':
            if ir_dry_run:
                _print_ir_dry_run('Disable RDP', commands=['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f'])
                continue
            res = run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)
            console.print('RDP disabled' if not res or '_error' not in res[0] else f'Error: {res[0]["_error"]}')
        elif choice == '17':
            if ir_dry_run:
                _print_ir_dry_run('Enable RDP', commands=['reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'])
                continue
            res = run_command('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f', shell=True)
            console.print('RDP enabled' if not res or '_error' not in res[0] else f'Error: {res[0]["_error"]}')
        elif choice == '18':
            # Enable Windows Defender with confirmation and status check
            console.print('[cyan]Current Windows Defender Status:[/cyan]')
            res_status = run_command('powershell -command "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | Format-List"', shell=True)
            if res_status and isinstance(res_status, list) and '_output' in res_status[0]:
                console.print(res_status[0]['_output'])
            if ir_dry_run:
                _print_ir_dry_run('Enable Defender real-time monitoring', commands=['powershell -command "Set-MpPreference -DisableRealtimeMonitoring $false"'])
                continue
            
            if console.input('Enable Windows Defender real-time monitoring? (y/N): ').strip().lower() == 'y':
                res = run_command('powershell -command "Set-MpPreference -DisableRealtimeMonitoring $false"', shell=True)
                if not res or '_error' not in res[0]:
                    console.print('[green]Windows Defender real-time monitoring enabled.[/green]')
                    # Show updated status
                    res_status = run_command('powershell -command "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | Format-List"', shell=True)
                    if res_status and isinstance(res_status, list) and '_output' in res_status[0]:
                        console.print('[cyan]Updated Status:[/cyan]')
                        console.print(res_status[0]['_output'])
                else:
                    console.print(f'[red]Error: {res[0]["_error"]}[/red]')
            else:
                console.print('Cancelled.')
        elif choice == '19':
            # Disable Windows Defender with confirmation and status check
            console.print('[cyan]Current Windows Defender Status:[/cyan]')
            res_status = run_command('powershell -command "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | Format-List"', shell=True)
            if res_status and isinstance(res_status, list) and '_output' in res_status[0]:
                console.print(res_status[0]['_output'])
            if ir_dry_run:
                _print_ir_dry_run('Disable Defender real-time monitoring', commands=['powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"'])
                continue
            
            console.print('[red]⚠️  WARNING: Disabling Antivirus reduces system security![/red]')
            if console.input('Are you absolutely sure you want to disable Windows Defender? (y/N): ').strip().lower() == 'y':
                res = run_command('powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"', shell=True)
                if not res or '_error' not in res[0]:
                    console.print('[yellow]Windows Defender real-time monitoring disabled.[/yellow]')
                    # Show updated status
                    res_status = run_command('powershell -command "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled | Format-List"', shell=True)
                    if res_status and isinstance(res_status, list) and '_output' in res_status[0]:
                        console.print('[cyan]Updated Status:[/cyan]')
                        console.print(res_status[0]['_output'])
                else:
                    console.print(f'[red]Error: {res[0]["_error"]}[/red]')
            else:
                console.print('Cancelled.')
        elif choice == '20':
            if not server_mode:
                break
            cmd = (
                'powershell -NoProfile -Command "Get-SmbSession | '
                'Select-Object SessionId,ClientComputerName,ClientUserName,NumOpens,Dialect | '
                'ConvertTo-Json -Depth 6"'
            )
            rows, err = _json_rows_from_command(cmd)
            if rows:
                display_and_export('ir_server_smb_sessions', rows)
            else:
                console.print(f'[yellow]No SMB sessions found or command unavailable: {err}[/yellow]')
        elif choice == '21' and server_mode:
            sid = console.input('SMB SessionId to close: ').strip()
            if not sid.isdigit():
                console.print('[red]Invalid SessionId[/red]')
                continue
            if ir_dry_run:
                cmd = f'powershell -NoProfile -Command "Close-SmbSession -SessionId {sid} -Force"'
                _print_ir_dry_run('Close SMB session', details={'SessionId': sid}, commands=[cmd])
                continue
            if console.input(f'Close SMB session {sid}? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            cmd = f'powershell -NoProfile -Command "Close-SmbSession -SessionId {sid} -Force"'
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to close SMB session: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Closed SMB session {sid}[/green]')
        elif choice == '22' and server_mode:
            cmds = [
                'powershell -NoProfile -Command "Disable-PSRemoting -Force"',
                'sc stop WinRM',
                'sc config WinRM start= disabled',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Disable WinRM service and listener', commands=cmds)
                continue
            if console.input('Disable WinRM service and listener? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            failed = []
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    failed.append(res[0]['_error'])
            if failed:
                console.print('[yellow]WinRM disable completed with warnings:[/yellow]')
                for f in failed:
                    console.print(f'  - {f}')
            else:
                console.print('[green]WinRM disabled successfully.[/green]')
        elif choice == '23' and server_mode:
            cmds = [
                'sc config WinRM start= auto',
                'sc start WinRM',
                'powershell -NoProfile -Command "Enable-PSRemoting -Force"',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Enable WinRM service and listener', commands=cmds)
                continue
            if console.input('Enable WinRM service and listener? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            failed = []
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    failed.append(res[0]['_error'])
            if failed:
                console.print('[yellow]WinRM enable completed with warnings:[/yellow]')
                for f in failed:
                    console.print(f'  - {f}')
            else:
                console.print('[green]WinRM enabled successfully.[/green]')
        elif choice == '24' and server_mode:
            console.print('[red]Warning:[/red] This can cut off remote management access.')
            cmds = [
                'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound',
                'netsh advfirewall set allprofiles state on',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Emergency network isolation', commands=cmds)
                continue
            confirm = console.input('Apply emergency isolation (block all inbound and outbound)? (y/N): ').strip().lower()
            if confirm != 'y':
                console.print('Cancelled.')
                continue
            failed = []
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    failed.append(res[0]['_error'])
            if failed:
                console.print('[red]Isolation encountered errors:[/red]')
                for f in failed:
                    console.print(f'  - {f}')
            else:
                console.print('[green]Emergency isolation policy applied.[/green]')
        elif choice == '25' and server_mode:
            console.print('[yellow]Restoring default restrictive policy: block inbound, allow outbound.[/yellow]')
            cmds = [
                'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound',
                'netsh advfirewall set allprofiles state on',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Rollback firewall isolation policy', commands=cmds)
                continue
            if console.input('Proceed with firewall rollback? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            failed = []
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    failed.append(res[0]['_error'])
            if failed:
                console.print('[red]Rollback encountered errors:[/red]')
                for f in failed:
                    console.print(f'  - {f}')
            else:
                console.print('[green]Firewall policy rolled back successfully.[/green]')
        elif choice == '26' and server_mode:
            user = console.input('User account to disable (samAccountName or local username): ').strip()
            if not user:
                console.print('[red]No user specified[/red]')
                continue
            is_domain = console.input('Is this a domain account? (y/N): ').strip().lower() == 'y'
            if ir_dry_run:
                if is_domain:
                    cmd_preview = f'net user "{user}" /domain /active:no'
                else:
                    cmd_preview = f'powershell -NoProfile -Command "Disable-LocalUser -Name \"{user}\"" (fallback: net user "{user}" /active:no)'
                _print_ir_dry_run('Disable user account', details={'User': user, 'Domain Account': is_domain}, commands=[cmd_preview])
                continue
            if console.input(f'Disable account "{user}"? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            if is_domain:
                cmd = f'net user "{user}" /domain /active:no'
                res = run_command(cmd, shell=True)
            else:
                cmd_local = f'powershell -NoProfile -Command "Disable-LocalUser -Name \"{user}\""'
                res = run_command(cmd_local, shell=True)
                if res and isinstance(res, list) and '_error' in res[0]:
                    res = run_command(f'net user "{user}" /active:no', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to disable account: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Account disabled: {user}[/green]')
        elif choice == '27' and server_mode:
            task_name = console.input('Scheduled task name/path (e.g. \\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan): ').strip()
            if not task_name:
                console.print('[red]No task name provided[/red]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Disable scheduled task', details={'Task': task_name}, commands=[f'schtasks /Change /TN "{task_name}" /Disable'])
                continue
            if console.input(f'Disable scheduled task "{task_name}"? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            res = run_command(f'schtasks /Change /TN "{task_name}" /Disable', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to disable task: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Scheduled task disabled: {task_name}[/green]')
        elif choice == '28' and server_mode:
            console.print('[cyan]Active terminal sessions:[/cyan]')
            sessions = run_command('query user', shell=True)
            if sessions and isinstance(sessions, list) and '_output' in sessions[0]:
                console.print(sessions[0]['_output'])
            else:
                serr = sessions[0].get('_error', 'Unable to query sessions') if sessions and isinstance(sessions, list) else 'Unable to query sessions'
                console.print(f'[yellow]{serr}[/yellow]')

            sid = console.input('Session ID to log off: ').strip()
            if not sid.isdigit():
                console.print('[red]Invalid Session ID[/red]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Log off terminal session', details={'Session ID': sid}, commands=[f'logoff {sid}'])
                continue
            if console.input(f'Log off session {sid}? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            res = run_command(f'logoff {sid}', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to log off session: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Logged off session {sid}[/green]')
        elif choice == '29' and server_mode:
            user = console.input('Domain user to remove (samAccountName): ').strip()
            if not user:
                console.print('[red]No user specified[/red]')
                continue
            group = console.input('Privileged AD group (default: Domain Admins): ').strip() or 'Domain Admins'
            console.print('[yellow]Optional AD response:[/yellow] This modifies AD group membership.')
            cmd = (
                'powershell -NoProfile -Command "Import-Module ActiveDirectory -ErrorAction Stop; '
                f'Remove-ADGroupMember -Identity \"{group}\" -Members \"{user}\" -Confirm:$false"'
            )
            if ir_dry_run:
                _print_ir_dry_run('Remove AD group membership', details={'User': user, 'Group': group}, commands=[cmd])
                continue
            if console.input('Dry-run only (preview command without executing)? (y/N): ').strip().lower() == 'y':
                console.print('[cyan]Dry-run preview:[/cyan]')
                console.print(f'  Action : Remove AD group membership')
                console.print(f'  User   : {user}')
                console.print(f'  Group  : {group}')
                console.print(f'  Command: {cmd}')
                continue
            if console.input(f'Remove {user} from "{group}"? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to remove AD group membership: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Removed {user} from {group}[/green]')
        elif choice == '30' and server_mode:
            computer = console.input('Computer account to disable (e.g., SRV01$): ').strip()
            if not computer:
                console.print('[red]No computer account specified[/red]')
                continue
            console.print('[yellow]Optional AD response:[/yellow] This disables a domain computer object.')
            cmd = (
                'powershell -NoProfile -Command "Import-Module ActiveDirectory -ErrorAction Stop; '
                f'Disable-ADAccount -Identity \"{computer}\""'
            )
            if ir_dry_run:
                _print_ir_dry_run('Disable AD computer account', details={'Computer': computer}, commands=[cmd])
                continue
            if console.input('Dry-run only (preview command without executing)? (y/N): ').strip().lower() == 'y':
                console.print('[cyan]Dry-run preview:[/cyan]')
                console.print(f'  Action : Disable AD computer account')
                console.print(f'  Computer: {computer}')
                console.print(f'  Command : {cmd}')
                continue
            if console.input(f'Disable AD computer account "{computer}"? (y/N): ').strip().lower() != 'y':
                console.print('Cancelled.')
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to disable AD computer account: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Disabled AD computer account: {computer}[/green]')
        elif choice == '31' and server_mode:
            break
        else:
            console.print('[yellow]Invalid choice[/yellow]')


def _windows_list_user_accounts():
    """List local user account details on Windows with fallback to net user output."""
    cmd = (
        'powershell -NoProfile -Command '
        '"Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description '
        '| ConvertTo-Json -Depth 4"'
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('windows_ir_user_accounts', rows)
        return

    fallback = run_command('net user', shell=True)
    if fallback and isinstance(fallback, list) and '_output' in fallback[0]:
        display_and_export('windows_ir_user_accounts', [{'users_raw': fallback[0]['_output'][:12000]}])
    else:
        ferr = fallback[0].get('_error', '') if fallback and isinstance(fallback, list) else ''
        display_and_export('windows_ir_user_accounts', [{'status': 'Failed', 'error': err or ferr or 'Unable to list user accounts'}])


def user_management(ir_dry_run=False):
    """Windows user management submenu used by Incident Response option 12."""
    while True:
        console.print('\n[bold cyan]User management[/bold cyan]')
        console.print('1. List available users details')
        console.print('2. Disable/lock user account')
        console.print('3. Enable/unlock user account')
        console.print('4. Add user account')
        console.print('5. Remove user account')
        console.print('6. Remove user from group')
        console.print('7. Back')
        sub = console.input('Choose (1-7): ').strip()

        if sub == '1':
            _windows_list_user_accounts()
        elif sub == '2':
            user = console.input('Username to disable/lock: ').strip()
            if not user:
                console.print('[red]No username provided[/red]')
                continue
            cmds = [
                f'powershell -NoProfile -Command "Disable-LocalUser -Name \"{user}\""',
                f'net user "{user}" /active:no',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Disable/lock Windows user account', details={'user': user}, commands=cmds)
                continue
            ok = False
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' not in res[0]:
                    ok = True
                    break
            if ok:
                console.print(f'[green]Account disabled/locked: {user}[/green]')
            else:
                console.print(f'[red]Failed to disable/lock account: {user}[/red]')
        elif sub == '3':
            user = console.input('Username to enable/unlock: ').strip()
            if not user:
                console.print('[red]No username provided[/red]')
                continue
            cmds = [
                f'powershell -NoProfile -Command "Enable-LocalUser -Name \"{user}\""',
                f'net user "{user}" /active:yes',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Enable/unlock Windows user account', details={'user': user}, commands=cmds)
                continue
            ok = False
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' not in res[0]:
                    ok = True
                    break
            if ok:
                console.print(f'[green]Account enabled/unlocked: {user}[/green]')
            else:
                console.print(f'[red]Failed to enable/unlock account: {user}[/red]')
        elif sub == '4':
            user = console.input('Username to add: ').strip()
            if not user:
                console.print('[red]No username provided[/red]')
                continue
            password = console.input('Password (leave blank for disabled-password placeholder): ').strip() or 'Temp#12345'
            cmd = f'net user "{user}" "{password}" /add'
            if ir_dry_run:
                _print_ir_dry_run('Add Windows user account', details={'user': user}, commands=[cmd])
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to add account: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Account added: {user}[/green]')
        elif sub == '5':
            user = console.input('Username to remove: ').strip()
            if not user:
                console.print('[red]No username provided[/red]')
                continue
            cmd = f'net user "{user}" /delete'
            if ir_dry_run:
                _print_ir_dry_run('Remove Windows user account', details={'user': user}, commands=[cmd])
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to remove account: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Account removed: {user}[/green]')
        elif sub == '6':
            user = console.input('Username: ').strip()
            group_name = console.input('Group to remove user from: ').strip()
            if not user or not group_name:
                console.print('[red]Username and group are required[/red]')
                continue
            cmds = [
                f'net localgroup "{group_name}" "{user}" /delete',
                f'powershell -NoProfile -Command "Remove-LocalGroupMember -Group \"{group_name}\" -Member \"{user}\""',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Remove Windows user from group', details={'user': user, 'group': group_name}, commands=cmds)
                continue
            ok = False
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' not in res[0]:
                    ok = True
                    break
            if ok:
                console.print(f'[green]Removed {user} from group {group_name}[/green]')
            else:
                console.print(f'[red]Failed to remove {user} from group {group_name}[/red]')
        elif sub == '7':
            break
        else:
            console.print('[yellow]Invalid choice[/yellow]')


def incident_response_menu_linux():
    """Linux-focused incident response actions with session-level dry-run."""
    ir_dry_run = console.input('Enable dry-run for all high-impact actions this IR session? (y/N): ').strip().lower() == 'y'
    if ir_dry_run:
        console.print('[cyan]Dry-run is ON for this Linux IR session.[/cyan]')

    while True:
        console.print('\n[bold yellow]Linux Incident Response Actions:[/bold yellow]')
        console.print('1.  List processes')
        console.print('2.  Kill process by PID')
        console.print('3.  Run command')
        console.print('4.  List existing firewall rules')
        console.print('5.  Block IP')
        console.print('6.  Unblock IP')
        console.print('7.  Stop service')
        console.print('8.  Remove/delete service')
        console.print('9.  Network connections snapshot')
        console.print('10. Disable SSH service')
        console.print('11. Enable SSH service')
        console.print('12. Disable Telnet service (legacy/unsupported on most macOS builds)')
        console.print('13. Enable Telnet service (legacy/unsupported on most macOS builds)')
        console.print('14. Disable FTP service (legacy/unsupported on most macOS builds)')
        console.print('15. Enable FTP service (legacy/unsupported on most macOS builds)')
        console.print('16. Disable RDP / Screen Sharing (legacy labels may be unsupported)')
        console.print('17. Enable RDP / Screen Sharing (legacy labels may be unsupported)')
        console.print('18. Isolate host (safe mode)')
        console.print('19. Rollback host isolation')
        console.print('20. User management')
        console.print('21. Remove suspicious cron entry')
        console.print('22. Kill process by port')
        console.print('23. Quarantine file')
        console.print('24. Restore quarantined file')
        console.print('25. Back to main menu')
        choice = console.input('Choose action (1-25): ').strip()

        if choice == '1':
            out, err = _run_first_success([
                'ps -eo pid,ppid,user,comm,args --sort=-pid | head -n 300',
                'ps aux | head -n 300',
            ])
            if out:
                display_and_export('linux_ir_processes', _rows_from_lines('process', out.splitlines(), field='process'))
            else:
                console.print(f'[red]Process listing failed: {err}[/red]')

        elif choice == '2':
            pid = console.input('PID to kill: ').strip()
            if not pid.isdigit():
                console.print('[red]Invalid PID[/red]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Kill Linux process by PID', details={'PID': pid}, commands=[f'kill -9 {pid}'])
                continue
            res = run_command(f'kill -9 {pid}', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to kill process: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Process terminated: {pid}[/green]')

        elif choice == '3':
            cmd = console.input('Command to run: ').strip()
            if not cmd:
                console.print('[yellow]No command entered, skipping.[/yellow]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Run Linux command', details={'Command': cmd}, commands=[cmd])
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Command failed: {res[0]['_error']}[/red]")
            else:
                console.print(res[0].get('_output', '') if res and isinstance(res, list) else '')

        elif choice == '4':
            rows = _linux_collect_firewall_rules_rows()
            if not rows:
                rows = [{'status': 'No supported firewall backend detected (iptables/nft/ufw/firewall-cmd)'}]
            display_and_export('linux_ir_firewall_rules', rows)

        elif choice == '5':
            ip = console.input('IP address to block: ').strip()
            if not ip:
                console.print('[red]No IP entered[/red]')
                continue
            direction_choice = console.input('Direction to block (1=inbound, 2=outbound): ').strip()
            if direction_choice == '1':
                direction_label = 'inbound'
                cmds = [
                    f'iptables -I INPUT -s {ip} -j DROP',
                    f'nft add rule inet filter input ip saddr {ip} drop',
                ]
            elif direction_choice == '2':
                direction_label = 'outbound'
                cmds = [
                    f'iptables -I OUTPUT -d {ip} -j DROP',
                    f'nft add rule inet filter output ip daddr {ip} drop',
                ]
            else:
                console.print('[yellow]Invalid direction choice[/yellow]')
                continue

            existing = _linux_firewall_ip_matches(ip, direction_label)
            drop_like = [r for r in existing if _linux_is_drop_like_rule(r)]
            if drop_like:
                console.print(f'[yellow]A matching {direction_label} blocking rule already exists for {ip} ({len(drop_like)} match(es)).[/yellow]')
                if console.input('Create duplicate rule anyway? (y/N): ').strip().lower() != 'y':
                    console.print('[cyan]Skipping duplicate firewall rule creation.[/cyan]')
                    continue

            if ir_dry_run:
                _print_ir_dry_run('Block IP on Linux', details={'IP': ip, 'Direction': direction_label}, commands=cmds)
                continue
            ok = False
            last_err = ''
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' not in res[0]:
                    ok = True
                    break
                if res and isinstance(res, list):
                    last_err = res[0].get('_error', '')
            if ok:
                console.print(f'[green]Blocked {direction_label} IP: {ip}[/green]')
            else:
                console.print(f'[red]Failed to block IP: {last_err or "No firewall backend succeeded"}[/red]')

        elif choice == '6':
            ip = console.input('IP address to unblock: ').strip()
            if not ip:
                console.print('[red]No IP entered[/red]')
                continue

            any_matches = _linux_firewall_ip_matches(ip)
            if not any_matches:
                console.print(f'[yellow]No existing firewall rules found for IP: {ip}[/yellow]')
                continue

            inbound_count = len(_linux_firewall_ip_matches(ip, 'inbound'))
            outbound_count = len(_linux_firewall_ip_matches(ip, 'outbound'))
            console.print(f'[cyan]Existing matches for {ip}: inbound={inbound_count}, outbound={outbound_count}, total={len(any_matches)}[/cyan]')

            direction_choice = console.input('Direction to unblock (1=inbound, 2=outbound): ').strip()
            if direction_choice == '1':
                direction_label = 'inbound'
                if inbound_count == 0:
                    console.print(f'[yellow]No inbound rules found for {ip}; skipping unblock.[/yellow]')
                    continue
                cmds = [
                    f'iptables -D INPUT -s {ip} -j DROP',
                ]
            elif direction_choice == '2':
                direction_label = 'outbound'
                if outbound_count == 0:
                    console.print(f'[yellow]No outbound rules found for {ip}; skipping unblock.[/yellow]')
                    continue
                cmds = [
                    f'iptables -D OUTPUT -d {ip} -j DROP',
                ]
            else:
                console.print('[yellow]Invalid direction choice[/yellow]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Unblock IP on Linux', details={'IP': ip, 'Direction': direction_label}, commands=cmds)
                continue
            res = run_command(cmds[0], shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[yellow]iptables remove failed: {res[0]['_error']}[/yellow]")
                console.print('[yellow]If nftables is used, remove corresponding nft rule manually.[/yellow]')
            else:
                console.print(f'[green]Unblocked {direction_label} IP (iptables): {ip}[/green]')

        elif choice == '7':
            svc = console.input('Service name to stop: ').strip()
            if not svc:
                console.print('[red]No service name entered[/red]')
                continue
            cmds = [f'systemctl stop {svc}', f'service {svc} stop']
            if ir_dry_run:
                _print_ir_dry_run('Stop Linux service', details={'Service': svc}, commands=cmds)
                continue
            ok = False
            last_err = ''
            for c in cmds:
                res = run_command(c, shell=True)
                if res and isinstance(res, list) and '_error' not in res[0]:
                    ok = True
                    break
                if res and isinstance(res, list):
                    last_err = res[0].get('_error', '')
            if ok:
                console.print(f'[green]Stopped service: {svc}[/green]')
            else:
                console.print(f'[red]Failed to stop service: {last_err or "No service manager command succeeded"}[/red]')

        elif choice == '8':
            _linux_remove_service_definition(ir_dry_run=ir_dry_run)

        elif choice == '9':
            out, err = _run_first_success([
                'ss -tunap',
                'netstat -tunap',
            ])
            if out:
                rows = _rows_from_lines('connection', out.splitlines(), field='connection')
                display_and_export('linux_ir_network_snapshot', rows)
            else:
                console.print(f'[red]Network snapshot failed: {err}[/red]')

        elif choice == '10':
            if not _linux_precheck_service_toggle(['sshd', 'ssh'], 'Disable SSH service'):
                continue
            _linux_service_toggle(['sshd', 'ssh'], action='disable', ir_dry_run=ir_dry_run, verify_ports=['22'])

        elif choice == '11':
            if not _linux_precheck_service_toggle(['sshd', 'ssh'], 'Enable SSH service'):
                continue
            _linux_service_toggle(['sshd', 'ssh'], action='enable', ir_dry_run=ir_dry_run, verify_ports=['22'])

        elif choice == '12':
            if not _linux_precheck_service_toggle(['telnet.socket', 'telnetd.socket', 'telnet', 'telnetd', 'xinetd', 'openbsd-inetd'], 'Disable Telnet service'):
                continue
            _linux_service_toggle(['telnet.socket', 'telnetd.socket', 'telnet', 'telnetd', 'xinetd', 'openbsd-inetd'], action='disable', ir_dry_run=ir_dry_run, verify_ports=['23'], service_family='telnet')

        elif choice == '13':
            if not _linux_precheck_service_toggle(['telnet.socket', 'telnetd.socket', 'telnet', 'telnetd', 'xinetd', 'openbsd-inetd'], 'Enable Telnet service'):
                continue
            _linux_service_toggle(['telnet.socket', 'telnetd.socket', 'telnet', 'telnetd', 'xinetd', 'openbsd-inetd'], action='enable', ir_dry_run=ir_dry_run, verify_ports=['23'], service_family='telnet')

        elif choice == '14':
            if not _linux_precheck_service_toggle(['vsftpd', 'vsftpd.service', 'proftpd', 'proftpd.service', 'pure-ftpd', 'xinetd', 'openbsd-inetd'], 'Disable FTP service'):
                continue
            _linux_service_toggle(['vsftpd', 'vsftpd.service', 'proftpd', 'proftpd.service', 'pure-ftpd', 'xinetd', 'openbsd-inetd'], action='disable', ir_dry_run=ir_dry_run, verify_ports=['21'])

        elif choice == '15':
            if not _linux_precheck_service_toggle(['vsftpd', 'vsftpd.service', 'proftpd', 'proftpd.service', 'pure-ftpd', 'xinetd', 'openbsd-inetd'], 'Enable FTP service'):
                continue
            _linux_service_toggle(['vsftpd', 'vsftpd.service', 'proftpd', 'proftpd.service', 'pure-ftpd', 'xinetd', 'openbsd-inetd'], action='enable', ir_dry_run=ir_dry_run, verify_ports=['21'])

        elif choice == '16':
            if not _linux_precheck_service_toggle(['xrdp', 'xrdp.service', 'xrdp-sesman', 'xrdp-sesman.service'], 'Disable RDP service'):
                continue
            _linux_service_toggle(['xrdp', 'xrdp.service', 'xrdp-sesman', 'xrdp-sesman.service'], action='disable', ir_dry_run=ir_dry_run, verify_ports=['3389'])

        elif choice == '17':
            if not _linux_precheck_service_toggle(['xrdp', 'xrdp.service', 'xrdp-sesman', 'xrdp-sesman.service'], 'Enable RDP service'):
                continue
            _linux_service_toggle(['xrdp', 'xrdp.service', 'xrdp-sesman', 'xrdp-sesman.service'], action='enable', ir_dry_run=ir_dry_run, verify_ports=['3389'])

        elif choice == '18':
            _linux_isolate_host_safe_mode(ir_dry_run=ir_dry_run)

        elif choice == '19':
            _linux_run_last_isolation_rollback(ir_dry_run=ir_dry_run)

        elif choice == '20':
            _linux_user_management_menu(ir_dry_run=ir_dry_run)

        elif choice == '21':
            _linux_remove_cron_entry(ir_dry_run=ir_dry_run)

        elif choice == '22':
            _linux_kill_by_port(ir_dry_run=ir_dry_run)

        elif choice == '23':
            _linux_quarantine_file(ir_dry_run=ir_dry_run)

        elif choice == '24':
            _linux_restore_quarantined_file(ir_dry_run=ir_dry_run)

        elif choice == '25':
            break
        else:
            console.print('[yellow]Invalid choice[/yellow]')


def _run_first_success(commands):
    """Run first command that succeeds and return (output, error)."""
    last_err = ''
    for cmd in commands:
        res = run_command(cmd, shell=True)
        if res and isinstance(res, list) and '_output' in res[0]:
            return res[0]['_output'], ''
        if res and isinstance(res, list) and '_error' in res[0]:
            last_err = res[0]['_error']
    return '', last_err or 'No command succeeded'


def _run_shell_command_timeout(cmd, timeout_sec=20):
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout_sec,
        )
        out = (proc.stdout or '').strip()
        err = (proc.stderr or '').strip()
        if proc.returncode != 0:
            return '', err or out or f'returncode {proc.returncode}'
        return out, ''
    except subprocess.TimeoutExpired:
        return '', f'timeout after {timeout_sec}s'
    except Exception as e:
        return '', str(e)


def _rows_from_lines(key, lines, field='line'):
    rows = []
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if s:
            rows.append({'index': i, field: s})
    if not rows:
        rows = [{'status': f'No {key} data found'}]
    return rows


def _linux_execute_command_candidates(action, commands, ir_dry_run=False, details=None):
    """Execute command candidates until one succeeds."""
    if ir_dry_run:
        _print_ir_dry_run(action, details=details, commands=commands)
        return True

    last_err = ''
    for cmd in commands:
        res = run_command(cmd, shell=True)
        if res and isinstance(res, list) and '_error' not in res[0]:
            return True
        if res and isinstance(res, list):
            last_err = res[0].get('_error', '')
    if last_err:
        console.print(f'[red]{action} failed: {last_err}[/red]')
    return False


def _linux_execute_command_series(action, commands, ir_dry_run=False, details=None):
    """Execute every command in a series and report the final status."""
    if ir_dry_run:
        _print_ir_dry_run(action, details=details, commands=commands)
        return True

    last_err = ''
    any_success = False
    for cmd in commands:
        res = run_command(cmd, shell=True)
        if res and isinstance(res, list) and '_error' not in res[0]:
            any_success = True
        elif res and isinstance(res, list):
            last_err = res[0].get('_error', '') or last_err

    if not any_success and last_err:
        console.print(f'[red]{action} failed: {last_err}[/red]')
    return any_success


def _linux_detect_firewall_backend():
    for cmd in ('iptables', 'nft', 'ufw', 'firewall-cmd'):
        if _linux_has_command(cmd):
            return cmd
    return ''


def _linux_package_installed(package_name):
    checks = [
        f'dpkg-query -W {shlex.quote(package_name)} >/dev/null 2>&1 && echo yes || echo no',
        f'rpm -q {package_name} >/dev/null 2>&1 && echo yes || echo no',
    ]
    for chk in checks:
        res = run_command(chk, shell=True)
        if res and isinstance(res, list) and '_output' in res[0] and res[0]['_output'].strip().lower() == 'yes':
            return True
    return False


def _linux_service_presence_hint(service_candidates, package_candidates=None):
    found_services = []
    expanded_candidates = _linux_expand_service_candidates(service_candidates)
    if _linux_has_command('systemctl'):
        known_units = set()
        listed = run_command('systemctl list-unit-files --no-pager --no-legend', shell=True)
        if listed and isinstance(listed, list) and '_output' in listed[0]:
            for ln in listed[0]['_output'].splitlines():
                s = ln.strip()
                if not s:
                    continue
                known_units.add(s.split()[0])

        for svc in expanded_candidates:
            if svc in known_units:
                found_services.append(svc)
                continue
            res = run_command(f'systemctl status {svc} >/dev/null 2>&1 && echo yes || echo no', shell=True)
            if res and isinstance(res, list) and '_output' in res[0] and res[0]['_output'].strip().lower() == 'yes':
                found_services.append(svc)
    if not found_services and _linux_has_command('service'):
        status = run_command('service --status-all 2>/dev/null', shell=True)
        output = status[0].get('_output', '') if status and isinstance(status, list) else ''
        for svc in expanded_candidates:
            if svc.replace('.service', '').replace('.socket', '') in output:
                found_services.append(svc)

    found_packages = []
    for pkg in package_candidates or []:
        if _linux_package_installed(pkg):
            found_packages.append(pkg)

    return found_services, found_packages


def _linux_related_package_candidates(service_candidates):
    package_candidates = {
        'sshd': ['openssh-server'],
        'ssh': ['openssh-server'],
        'ssh.service': ['openssh-server'],
        'sshd.service': ['openssh-server'],
        'ssh.socket': ['openssh-server'],
        'sshd.socket': ['openssh-server'],
        'telnet.socket': ['telnetd', 'xinetd', 'inetutils-telnetd', 'openbsd-inetd'],
        'telnet': ['telnetd', 'xinetd', 'inetutils-telnetd', 'openbsd-inetd'],
        'telnetd': ['telnetd', 'xinetd', 'inetutils-telnetd', 'openbsd-inetd'],
        'telnetd.service': ['telnetd', 'xinetd', 'openbsd-inetd', 'inetutils-telnetd'],
        'telnetd.socket': ['telnetd', 'xinetd', 'openbsd-inetd', 'inetutils-telnetd'],
        'xinetd': ['xinetd'],
        'openbsd-inetd': ['openbsd-inetd', 'inetutils-inetd'],
        'vsftpd': ['vsftpd'],
        'vsftpd.service': ['vsftpd'],
        'proftpd': ['proftpd'],
        'proftpd.service': ['proftpd'],
        'pure-ftpd': ['pure-ftpd'],
        'pure-ftpd.service': ['pure-ftpd'],
        'pureftpd': ['pure-ftpd'],
        'xrdp': ['xrdp', 'xorgxrdp'],
        'xrdp.service': ['xrdp', 'xorgxrdp'],
        'xrdp-sesman': ['xrdp', 'xorgxrdp'],
        'xrdp-sesman.service': ['xrdp', 'xorgxrdp'],
        'smbd': ['samba'],
    }
    pkg_candidates = []
    for svc in service_candidates:
        pkg_candidates.extend(package_candidates.get(svc, []))
    return sorted(set(pkg_candidates))


def _linux_precheck_service_toggle(service_candidates, action_label):
    """Warn before trying service commands when service/package is missing."""
    expanded_candidates = _linux_expand_service_candidates(service_candidates)
    pkg_candidates = _linux_related_package_candidates(expanded_candidates)
    found_services, found_packages = _linux_service_presence_hint(expanded_candidates, pkg_candidates)

    if found_services:
        return True

    console.print(f'[yellow]Pre-check: no active/known service units detected for {action_label}.[/yellow]')
    if found_packages:
        console.print(f'[yellow]Related package(s) installed: {", ".join(found_packages)}[/yellow]')
        console.print('[yellow]Unit names may differ. You can continue to try common unit names.[/yellow]')
    else:
        console.print('[yellow]No related packages detected for this service family.[/yellow]')
        pkg_mgr = ''
        if _linux_has_command('apt'):
            pkg_mgr = 'apt'
        elif _linux_has_command('dnf'):
            pkg_mgr = 'dnf'
        elif _linux_has_command('yum'):
            pkg_mgr = 'yum'
        elif _linux_has_command('pacman'):
            pkg_mgr = 'pacman'

        if pkg_candidates and pkg_mgr:
            if pkg_mgr == 'apt':
                console.print(f'[dim]Install hint: sudo apt update && sudo apt install {" ".join(pkg_candidates)}[/dim]')
            elif pkg_mgr in ('dnf', 'yum'):
                console.print(f'[dim]Install hint: sudo {pkg_mgr} install {" ".join(pkg_candidates)}[/dim]')
            elif pkg_mgr == 'pacman':
                console.print(f'[dim]Install hint: sudo pacman -S {" ".join(pkg_candidates)}[/dim]')

    return console.input('Continue anyway with service commands? (y/N): ').strip().lower() == 'y'


def _linux_service_toggle(service_candidates, action, ir_dry_run=False, verify_ports=None, service_family=None):
    """Enable/disable known service names across distro variants."""
    action = action.lower()
    expanded_candidates = _linux_expand_service_candidates(service_candidates)
    family_label = service_family or (service_candidates[0] if service_candidates else 'service')
    summary_unit = ''
    summary_enabled = 'unknown'
    summary_active = 'unknown'
    summary_ports = 'not checked'

    if action == 'disable':
        commands = [
            f'systemctl stop {svc}' for svc in expanded_candidates
        ] + [
            f'systemctl disable {svc}' for svc in expanded_candidates
        ] + [
            f'systemctl mask {svc}' for svc in expanded_candidates
        ] + [
            f'service {svc} stop' for svc in expanded_candidates if '.' not in svc
        ]
        op_name = f'Disable service(s): {", ".join(expanded_candidates)}'
    else:
        commands = [
            f'systemctl unmask {svc}' for svc in expanded_candidates
        ] + [
            f'systemctl enable {svc}' for svc in expanded_candidates
        ] + [
            f'systemctl start {svc}' for svc in expanded_candidates
        ] + [
            f'service {svc} start' for svc in expanded_candidates if '.' not in svc
        ]
        op_name = f'Enable service(s): {", ".join(expanded_candidates)}'

    pkg_candidates = _linux_related_package_candidates(service_candidates)

    success = _linux_execute_command_series(op_name, commands, ir_dry_run=ir_dry_run)
    if success and not ir_dry_run:
        svc, enabled, active = _linux_service_state(expanded_candidates)
        summary_unit = svc
        summary_enabled = enabled or 'unknown'
        summary_active = active or 'unknown'
        if svc:
            console.print(f'[green]{op_name} attempted. Verification: {svc} enabled={enabled}, active={active}[/green]')
        else:
            console.print(f'[yellow]{op_name} attempted, but no verifiable service state was detected.[/yellow]')

        if verify_ports:
            expected = [str(p) for p in verify_ports]
            present = _linux_get_expected_ports_with_retries(expected, attempts=3)
            if action == 'enable':
                if present:
                    console.print(f'[green]Port verification after enable: listening on {", ".join(present)}[/green]')
                    summary_ports = f'listening on {", ".join(present)}'
                else:
                    if service_family == 'telnet':
                        console.print('[yellow]Port verification after enable: Telnet is not exposed on port 23 yet. Trying common xinetd/inetd Telnet activation steps...[/yellow]')
                        _linux_telnet_post_config(action='enable', ir_dry_run=ir_dry_run)
                        present2 = _linux_get_expected_ports_with_retries(expected, attempts=4)
                        if present2:
                            console.print(f'[green]Telnet post-config verification: listening on {", ".join(present2)}[/green]')
                            summary_ports = f'listening on {", ".join(present2)}'
                        else:
                            console.print('[yellow]Telnet post-config verification: port 23 is still not listening. Telnet daemon package/config is likely missing on this distro profile.[/yellow]')
                            summary_ports = f'not listening on expected port(s): {", ".join(expected)}'
                            _linux_print_telnet_diagnostics()
                    else:
                        console.print(f'[yellow]Port verification after enable: expected port(s) {", ".join(expected)} are not listening. Service may be installed but not configured to expose externally.[/yellow]')
                        summary_ports = f'not listening on expected port(s): {", ".join(expected)}'
            else:
                if present:
                    if service_family == 'telnet':
                        console.print(f'[yellow]Port verification after disable: still listening on {", ".join(present)}. Trying Telnet deactivation in xinetd/inetd config...[/yellow]')
                        _linux_telnet_post_config(action='disable', ir_dry_run=ir_dry_run)
                        present2 = _linux_get_expected_ports_with_retries(expected, attempts=4)
                        if present2:
                            console.print(f'[yellow]Telnet post-config verification: still listening on {", ".join(present2)}[/yellow]')
                            summary_ports = f'still listening on {", ".join(present2)}'
                        else:
                            console.print(f'[green]Telnet post-config verification: expected port(s) {", ".join(expected)} are not listening.[/green]')
                            summary_ports = f'not listening on expected port(s): {", ".join(expected)}'
                    else:
                        console.print(f'[yellow]Port verification after disable: still listening on {", ".join(present)}[/yellow]')
                        summary_ports = f'still listening on {", ".join(present)}'
                else:
                    console.print(f'[green]Port verification after disable: expected port(s) {", ".join(expected)} are not listening.[/green]')
                    summary_ports = f'not listening on expected port(s): {", ".join(expected)}'

        _linux_print_service_action_summary(
            family=family_label,
            action=action,
            success=True,
            unit_name=summary_unit,
            enabled=summary_enabled,
            active=summary_active,
            ports_status=summary_ports,
        )
    elif not success and not ir_dry_run:
        found_services, found_packages = _linux_service_presence_hint(expanded_candidates, pkg_candidates)
        pkg_mgr = ''
        if _linux_has_command('apt'):
            pkg_mgr = 'apt'
        elif _linux_has_command('dnf'):
            pkg_mgr = 'dnf'
        elif _linux_has_command('yum'):
            pkg_mgr = 'yum'
        elif _linux_has_command('pacman'):
            pkg_mgr = 'pacman'

        if found_services:
            console.print(f'[yellow]Detected related service units: {", ".join(found_services)}[/yellow]')
        elif found_packages:
            console.print(f'[yellow]Related package(s) installed: {", ".join(found_packages)}[/yellow]')
            console.print('[yellow]Service unit names may differ on this distro. Check systemctl list-unit-files | grep -Ei "ssh|telnet|ftp"[/yellow]')
        else:
            console.print('[yellow]No matching service or package detected for requested toggle.[/yellow]')
            if pkg_candidates and pkg_mgr:
                if pkg_mgr == 'apt':
                    console.print(f'[dim]Install hint: sudo apt update && sudo apt install {" ".join(pkg_candidates)}[/dim]')
                elif pkg_mgr in ('dnf', 'yum'):
                    console.print(f'[dim]Install hint: sudo {pkg_mgr} install {" ".join(pkg_candidates)}[/dim]')
                elif pkg_mgr == 'pacman':
                    console.print(f'[dim]Install hint: sudo pacman -S {" ".join(pkg_candidates)}[/dim]')
        console.print(f'[red]{op_name} did not succeed with available service manager commands.[/red]')
        _linux_print_service_action_summary(
            family=family_label,
            action=action,
            success=False,
            unit_name=summary_unit,
            enabled=summary_enabled,
            active=summary_active,
            ports_status=summary_ports,
        )


def _linux_print_service_action_summary(family, action, success, unit_name='', enabled='unknown', active='unknown', ports_status='not checked'):
    """Print a standardized result block for Linux service toggle actions."""
    result = 'success' if success else 'failed'
    unit_display = unit_name or 'n/a'
    console.print('[cyan]Service action summary:[/cyan]')
    console.print(f'  - family: {family}')
    console.print(f'  - action: {action}')
    console.print(f'  - result: {result}')
    console.print(f'  - verified unit: {unit_display} (enabled={enabled}, active={active})')
    console.print(f'  - port status: {ports_status}')


def _linux_service_state(service_candidates):
    """Return best-effort enabled/active state for a service candidate list."""
    expanded_candidates = _linux_expand_service_candidates(service_candidates)
    for svc in expanded_candidates:
        enabled = ''
        active = ''

        if _linux_has_command('systemctl'):
            en = run_command(f'systemctl is-enabled {svc}', shell=True)
            ac = run_command(f'systemctl is-active {svc}', shell=True)
            if en and isinstance(en, list) and '_output' in en[0]:
                enabled = en[0]['_output'].strip()
            if ac and isinstance(ac, list) and '_output' in ac[0]:
                active = ac[0]['_output'].strip()
            # alias alone does not indicate effective runtime state; keep searching.
            if enabled.lower() == 'alias' and not active:
                continue
            if enabled or active:
                return svc, enabled, active

        if _linux_has_command('service'):
            ac = run_command(f'service {svc} status', shell=True)
            if ac and isinstance(ac, list) and '_output' in ac[0]:
                text = ac[0]['_output'].lower()
                if 'running' in text:
                    return svc, enabled or 'unknown', 'running'
                if 'stopped' in text or 'not running' in text:
                    return svc, enabled or 'unknown', 'stopped'

    return '', 'unknown', 'unknown'


def _linux_get_listening_ports():
    """Return a set of listening TCP/UDP ports from ss/netstat snapshot."""
    out, _ = _run_first_success(['ss -tulpn', 'netstat -tulpn'])
    ports = set()
    if not out:
        return ports
    for ln in out.splitlines():
        line = ln.strip()
        if not line:
            continue
        if 'LISTEN' not in line and not line.lower().startswith('udp'):
            continue
        m = re.search(r':(\d+)\b', line)
        if m:
            ports.add(m.group(1))
    return ports


def _linux_get_expected_ports_with_retries(expected_ports, attempts=3):
    """Retry listening-port snapshots to avoid transient false negatives after service restarts."""
    expected = [str(p) for p in (expected_ports or [])]
    found = set()
    tries = max(1, int(attempts or 1))
    for _ in range(tries):
        listening = _linux_get_listening_ports()
        for p in expected:
            if p in listening:
                found.add(p)
        if len(found) == len(expected):
            break
    return [p for p in expected if p in found]


def _linux_telnet_post_config(action='enable', ir_dry_run=False):
    """Attempt distro-common Telnet activation/deactivation for xinetd/inetd setups."""
    action = (action or '').lower().strip()
    if action == 'disable':
        cmds = [
            "if [ -f /etc/xinetd.d/telnet ]; then sed -i -E 's/^[[:space:]]*disable[[:space:]]*=.*/        disable         = yes/' /etc/xinetd.d/telnet; fi",
            'if command -v update-inetd >/dev/null 2>&1; then update-inetd --disable telnet || true; fi',
            'systemctl restart xinetd || true',
            'systemctl restart openbsd-inetd || true',
            'systemctl restart inetutils-inetd || true',
            'service xinetd restart || true',
            'service openbsd-inetd restart || true',
            'service inetutils-inetd restart || true',
        ]
        label = 'Telnet xinetd/inetd post-disable adjustments'
    else:
        cmds = [
            "if [ -d /etc/xinetd.d ] && [ ! -f /etc/xinetd.d/telnet ]; then TELNETD_BIN=\"$(command -v in.telnetd || command -v telnetd || echo /usr/sbin/in.telnetd)\"; printf '%s\\n' 'service telnet' '{' '    disable         = no' '    flags           = REUSE' '    socket_type     = stream' '    wait            = no' '    user            = root' \"    server          = ${TELNETD_BIN}\" '    log_on_failure  += USERID' '}' > /etc/xinetd.d/telnet; fi",
            "if [ -f /etc/xinetd.d/telnet ]; then sed -i -E 's/^[[:space:]]*disable[[:space:]]*=.*/        disable         = no/' /etc/xinetd.d/telnet; fi",
            'if command -v update-inetd >/dev/null 2>&1; then update-inetd --enable telnet || true; fi',
            'systemctl enable --now xinetd || true',
            'systemctl enable --now openbsd-inetd || true',
            'systemctl enable --now inetutils-inetd || true',
            'service xinetd start || true',
            'service openbsd-inetd start || true',
            'service inetutils-inetd start || true',
            'systemctl restart xinetd || true',
            'systemctl restart openbsd-inetd || true',
            'systemctl restart inetutils-inetd || true',
        ]
        label = 'Telnet xinetd/inetd post-enable adjustments'

    _linux_execute_command_series(label, cmds, ir_dry_run=ir_dry_run)


def _linux_print_telnet_diagnostics():
    """Print focused diagnostics when Telnet enable does not expose port 23."""
    has_telnetd = False
    for cmd in ('command -v in.telnetd', 'command -v telnetd'):
        res = run_command(cmd, shell=True)
        if res and isinstance(res, list) and res[0].get('_output', '').strip():
            has_telnetd = True
            break

    telnet_cfg_exists = False
    for p in ('/etc/xinetd.d/telnet', '/etc/inetd.conf'):
        chk = run_command(f'test -f {shlex.quote(p)} && echo yes || echo no', shell=True)
        if chk and isinstance(chk, list) and chk[0].get('_output', '').strip().lower() == 'yes':
            telnet_cfg_exists = True
            break

    pkg_candidates = _linux_related_package_candidates(['telnet', 'telnetd', 'xinetd', 'openbsd-inetd'])
    installed = []
    for pkg in pkg_candidates:
        if _linux_package_installed(pkg):
            installed.append(pkg)

    console.print('[cyan]Telnet diagnostics:[/cyan]')
    console.print(f'  - telnetd binary present: {"yes" if has_telnetd else "no"}')
    console.print(f'  - telnet config present (/etc/xinetd.d/telnet or /etc/inetd.conf): {"yes" if telnet_cfg_exists else "no"}')
    console.print(f'  - related packages installed: {", ".join(installed) if installed else "none detected"}')

    if _linux_has_command('apt'):
        console.print('[dim]Try: sudo apt update && sudo apt install telnetd xinetd inetutils-telnetd openbsd-inetd[/dim]')
    elif _linux_has_command('dnf'):
        console.print('[dim]Try: sudo dnf install telnet-server xinetd[/dim]')
    elif _linux_has_command('yum'):
        console.print('[dim]Try: sudo yum install telnet-server xinetd[/dim]')
    elif _linux_has_command('pacman'):
        console.print('[dim]Try: sudo pacman -S inetutils xinetd[/dim]')


def _linux_network_exposure_severity(port=None, process_name='', risk_hint='', base='Info'):
    """Return Linux network exposure severity from port/process/risk context."""
    pname = str(process_name or '').lower()
    hint = str(risk_hint or '').lower()
    base_norm = str(base or 'Info').strip().capitalize()

    p = None
    try:
        if port is not None and str(port).strip() != '':
            p = int(str(port))
    except Exception:
        p = None

    critical_ports = {23, 445, 512, 513, 514, 3306, 5432, 6379, 27017}
    high_ports = {21, 22, 25, 53, 80, 111, 139, 389, 443, 636, 3389, 5900, 8080, 8443}
    suspicious_proc = {'telnetd', 'in.telnetd', 'rshd', 'in.rshd', 'rexecd', 'in.rexecd', 'xinetd', 'smbd', 'nmbd', 'nc', 'ncat', 'socat'}

    if p in critical_ports or any(x in hint for x in ('legacy remote', 'critical', 'telnet', 'rexec', 'rsh')):
        return 'Critical'
    if p in high_ports or pname in suspicious_proc or any(x in hint for x in ('high', 'suspicious', 'exposed')):
        return 'High'
    if base_norm in ('Critical', 'High', 'Medium', 'Low', 'Info'):
        return base_norm
    return 'Medium'


def linux_exposed_services():
    """Detect externally exposed/risky services with service-state enrichment."""
    out, err = _run_first_success(['ss -tulpn', 'netstat -tulpn'])
    if not out:
        display_and_export('linux_exposed_services', [{'status': 'Failed', 'error': err}])
        return

    risk_ports = {
        '21': ('ftp', 'High', 'Plaintext file transfer'),
        '22': ('ssh', 'Medium', 'Remote administration surface'),
        '23': ('telnet', 'Critical', 'Plaintext remote shell service'),
        '139': ('smb', 'High', 'SMB NetBIOS exposure'),
        '445': ('smb', 'High', 'SMB service exposure'),
        '512': ('rsh', 'Critical', 'Legacy remote shell protocol'),
        '513': ('rlogin', 'Critical', 'Legacy remote login protocol'),
        '514': ('rexec', 'Critical', 'Legacy remote execution protocol'),
        '69': ('tftp', 'High', 'Unauthenticated file transfer service'),
        '2323': ('telnet-alt', 'Critical', 'Alternate Telnet port'),
        '3389': ('xrdp', 'High', 'Remote desktop exposure via XRDP'),
    }
    service_map = {
        'ssh': ['ssh.socket', 'sshd.socket', 'ssh.service', 'sshd.service', 'ssh', 'sshd'],
        'telnet': ['telnet.socket', 'telnetd.socket', 'telnet', 'telnetd', 'xinetd', 'openbsd-inetd'],
        'ftp': ['vsftpd', 'vsftpd.service', 'proftpd', 'proftpd.service', 'pure-ftpd', 'xinetd', 'openbsd-inetd'],
        'vsftpd': ['vsftpd'],
        'proftpd': ['proftpd'],
        'xinetd': ['xinetd'],
        'rsh': ['rsh', 'rsh.socket', 'xinetd'],
        'rexec': ['rexec', 'xinetd'],
        'smb': ['smbd', 'smb', 'samba', 'nmbd'],
        'xrdp': ['xrdp', 'xrdp.service', 'xrdp-sesman', 'xrdp-sesman.service'],
    }

    risk_by_process = {
        'sshd': ('ssh', 'Medium', 'Remote administration surface'),
        'ssh': ('ssh', 'Medium', 'Remote administration surface'),
        'telnetd': ('telnet', 'Critical', 'Plaintext remote shell service'),
        'in.telnetd': ('telnet', 'Critical', 'Plaintext remote shell service'),
        'vsftpd': ('vsftpd', 'High', 'FTP daemon exposure'),
        'proftpd': ('proftpd', 'High', 'FTP daemon exposure'),
        'xinetd': ('xinetd', 'High', 'Super-server may expose legacy services'),
        'rshd': ('rsh', 'Critical', 'Legacy remote shell protocol'),
        'in.rshd': ('rsh', 'Critical', 'Legacy remote shell protocol'),
        'rexecd': ('rexec', 'Critical', 'Legacy remote execution protocol'),
        'in.rexecd': ('rexec', 'Critical', 'Legacy remote execution protocol'),
        'smbd': ('smb', 'High', 'SMB service exposure'),
        'nmbd': ('smb', 'High', 'SMB NetBIOS service exposure'),
        'xrdp': ('xrdp', 'High', 'Remote desktop exposure via XRDP'),
        'xrdp-sesman': ('xrdp', 'Medium', 'XRDP session manager related exposure'),
    }

    rows = []
    for ln in out.splitlines():
        line = ln.strip()
        if not line:
            continue
        if 'LISTEN' not in line and not line.lower().startswith('udp'):
            continue
        m = re.search(r':(\d+)\b', line)
        if not m:
            continue

        port = m.group(1)
        proc_name = ''
        pid = ''
        mproc = re.search(r'users:\(\("([^\"]+)",pid=(\d+)', line)
        if mproc:
            proc_name = mproc.group(1)
            pid = mproc.group(2)
        else:
            mn = re.search(r'\s(\d+)/([^\s]+)$', line)
            if mn:
                pid = mn.group(1)
                proc_name = mn.group(2)

        proc_key = proc_name.lower().strip()
        app, base_severity, note = risk_by_process.get(proc_key, risk_ports.get(port, ('unknown', 'Info', 'Listening service')))
        matched_service = service_map.get(app, service_map.get(proc_key, []))
        svc_name, svc_enabled, svc_active = _linux_service_state(matched_service) if matched_service else ('', 'n/a', 'n/a')

        owner = ''
        if pid.isdigit():
            pres = run_command(f'ps -o user= -p {pid}', shell=True)
            if pres and isinstance(pres, list) and '_output' in pres[0]:
                owner = pres[0]['_output'].strip()

        rows.append({
            'service_name': svc_name or (app if app != 'unknown' else (proc_name or 'unknown')),
            'status': f'active={svc_active}; enabled={svc_enabled}',
            'port': port,
            'process': proc_name or 'unknown',
            'user': owner or 'unknown',
            'severity': _linux_network_exposure_severity(port=port, process_name=proc_name, risk_hint=note, base=base_severity),
            'evidence': line,
            'risk_hint': note,
        })

    if not rows:
        rows = [{'status': 'No exposed/risky listening services detected from socket snapshot'}]
    else:
        sev_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        rows.sort(key=lambda r: sev_rank.get(r.get('severity', 'Info'), 0), reverse=True)
    display_and_export('linux_exposed_services', rows)


def linux_sudoers_and_privilege_paths():
    rows = []
    out, err = _run_first_success([
        "grep -RniE 'NOPASSWD|ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 300",
        'cat /etc/sudoers 2>/dev/null | head -n 300',
    ])
    if out:
        for ln in out.splitlines():
            s = ln.strip()
            if not s or s.startswith('#'):
                continue
            rows.append({
                'entry': s,
                'risk_hint': 'Potential privileged path or NOPASSWD rule' if 'NOPASSWD' in s or 'ALL' in s else 'Review manually',
            })
    if not rows:
        rows = [{'status': 'No sudoers risk indicators found', 'error': err}]
    display_and_export('linux_sudoers_and_privilege_paths', rows)


def linux_user_startup_persistence():
    rows = []
    out, _ = _run_first_success([
        "ls -la /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.ssh/authorized_keys /home/*/.config/systemd/user 2>/dev/null",
        'ls -la /root/.bashrc /root/.profile /root/.ssh/authorized_keys 2>/dev/null',
    ])
    if out:
        rows.extend(_rows_from_lines('user_startup', out.splitlines(), field='entry'))

    cron_out, _ = _run_first_success([
        "for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null | sed 's/^/[cron '$u'] /'; done",
    ])
    if cron_out:
        for ln in cron_out.splitlines():
            if ln.strip():
                rows.append({'entry': ln.strip()})

    if not rows:
        rows = [{
            'status': 'No user startup persistence entries found',
            'note': 'No matching user shell startup files, authorized_keys, user systemd units, or user crontab entries were readable.',
        }]
    display_and_export('linux_user_startup_persistence', rows)


def linux_recent_privilege_events():
    checks = [
        (
            'journalctl',
            "journalctl --no-pager -n 400 2>/dev/null | grep -Ei 'sudo|su:|authentication failure|failed password|accepted password' | tail -n 250 || true",
        ),
        (
            '/var/log/auth.log',
            "tail -n 400 /var/log/auth.log 2>/dev/null | grep -Ei 'sudo|su:|authentication failure|failed password|accepted password' | tail -n 250 || true",
        ),
        (
            '/var/log/secure',
            "tail -n 400 /var/log/secure 2>/dev/null | grep -Ei 'sudo|su:|authentication failure|failed password|accepted password' | tail -n 250 || true",
        ),
    ]

    seen_source = []
    combined_lines = []
    last_err = ''

    for source, cmd in checks:
        seen_source.append(source)
        res = run_command(cmd, shell=True)
        if res and isinstance(res, list) and '_error' in res[0]:
            last_err = res[0].get('_error', '')
            continue
        if res and isinstance(res, list) and '_output' in res[0]:
            out = res[0]['_output'].strip()
            if out:
                combined_lines.extend(out.splitlines())

    if combined_lines:
        display_and_export(
            'linux_recent_privilege_events',
            _rows_from_lines('privilege_event', combined_lines, field='privilege_event')
        )
    else:
        display_and_export('linux_recent_privilege_events', [{
            'status': 'No matching privilege events in checked sources',
            'checked_sources': '; '.join(seen_source),
            'error': last_err,
        }])


def linux_kernel_modules():
    rows = []
    mod_out, mod_err = _run_first_success(['lsmod'])
    if mod_out:
        suspicious = ('rootkit', 'diamorphine', 'reptile', 'suterusu', 'hide')
        for ln in mod_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            risk = 'Suspicious module keyword' if any(k in s.lower() for k in suspicious) else ''
            rows.append({'module_row': s, 'risk_hint': risk})

    ver_out, _ = _run_first_success(["dmesg | grep -Ei 'module verification failed|taint' | tail -n 50"])
    if ver_out:
        for ln in ver_out.splitlines():
            if ln.strip():
                rows.append({'module_row': ln.strip(), 'risk_hint': 'Kernel module integrity warning'})

    if not rows:
        rows = [{'status': 'No kernel module data found', 'error': mod_err}]
    display_and_export('linux_kernel_modules', rows)


def linux_startup_autoruns():
    rows = []
    enabled_out, _ = _run_first_success([
        'systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | head -n 300',
        'service --status-all',
    ])
    if enabled_out:
        for ln in enabled_out.splitlines():
            s = ln.strip()
            if s:
                rows.append({'source': 'enabled_services', 'entry': s})

    rc_out, _ = _run_first_success(['cat /etc/rc.local 2>/dev/null'])
    if rc_out:
        for ln in rc_out.splitlines():
            s = ln.strip()
            if s and not s.startswith('#'):
                rows.append({'source': 'rc.local', 'entry': s})

    init_out, _ = _run_first_success(['ls -la /etc/init.d 2>/dev/null'])
    if init_out:
        for ln in init_out.splitlines():
            s = ln.strip()
            if s:
                rows.append({'source': 'init.d', 'entry': s})

    if not rows:
        rows = [{'status': 'No startup autorun indicators found'}]
    display_and_export('linux_startup_autoruns', rows)


def linux_network_route_arp_dns():
    rows = []
    route_out, _ = _run_first_success(['ip route', 'route -n'])
    if route_out:
        for ln in route_out.splitlines():
            if ln.strip():
                rows.append({'source': 'route', 'entry': ln.strip()})

    arp_out, _ = _run_first_success(['ip neigh', 'arp -an'])
    if arp_out:
        for ln in arp_out.splitlines():
            if ln.strip():
                rows.append({'source': 'arp', 'entry': ln.strip()})

    dns_out, _ = _run_first_success(['cat /etc/resolv.conf'])
    if dns_out:
        for ln in dns_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            hint = ''
            if s.lower().startswith('nameserver') and any(pub in s for pub in ('8.8.8.8', '1.1.1.1', '9.9.9.9')):
                hint = 'Public DNS configured; validate policy compliance'
            rows.append({'source': 'dns', 'entry': s, 'risk_hint': hint})

    if not rows:
        rows = [{'status': 'No route/ARP/DNS data found'}]
    display_and_export('linux_network_route_arp_dns', rows)


def linux_dns_cache_and_resolver():
    rows = []

    resolver_cmds = [
        'resolvectl status',
        'systemd-resolve --status',
        'nmcli dev show',
    ]
    resolver_out, _ = _run_first_success(resolver_cmds)
    if resolver_out:
        for ln in resolver_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            hint = ''
            low = s.lower()
            if 'dns server' in low or 'nameserver' in low:
                hint = 'Resolver/DNS server entry'
            elif 'search domains' in low or 'dns domain' in low:
                hint = 'Search/domain resolution path'
            elif 'cache' in low:
                hint = 'Resolver cache indicator'
            rows.append({'source': 'resolver_status', 'entry': s, 'risk_hint': hint})

    files_to_read = [
        '/etc/resolv.conf',
        '/etc/hosts',
        '/etc/nsswitch.conf',
        '/run/systemd/resolve/resolv.conf',
    ]
    for path in files_to_read:
        if not _linux_file_exists(path):
            continue
        res = run_command(f'cat {shlex.quote(path)}', shell=True)
        if not res or not isinstance(res, list) or '_output' not in res[0]:
            continue
        content = res[0]['_output']
        for ln in content.splitlines():
            s = ln.strip()
            if not s or s.startswith('#'):
                continue
            hint = ''
            low = s.lower()
            if path.endswith('resolv.conf') and low.startswith('nameserver'):
                if any(pub in low for pub in ('8.8.8.8', '1.1.1.1', '9.9.9.9')):
                    hint = 'Public DNS server in resolver config'
                else:
                    hint = 'Configured DNS server'
            elif path.endswith('hosts'):
                hint = 'Local name resolution entry'
            elif path.endswith('nsswitch.conf') and 'hosts:' in low:
                hint = 'Name resolution order'
            rows.append({'source': path, 'entry': s, 'risk_hint': hint})

    cache_cmds = [
        'nscd -g',
        'systemd-resolve --statistics',
        'resolvectl statistics',
    ]
    cache_out, _ = _run_first_success(cache_cmds)
    if cache_out:
        for ln in cache_out.splitlines():
            s = ln.strip()
            if s:
                rows.append({'source': 'resolver_cache', 'entry': s, 'risk_hint': 'Cache/lookup statistics'})

    if not rows:
        rows = [{'status': 'No DNS/resolver data found'}]
    display_and_export('linux_dns_cache_and_resolver', rows)


def linux_suspicious_network_listeners_by_process():
    rows = []
    out, err = _run_first_success(['ss -ltnup', 'netstat -tulpn'])
    if not out:
        display_and_export('linux_suspicious_network_listeners_by_process', [{'status': 'Failed', 'error': err}])
        return

    suspicious_terms = ('ssh', 'sshd', 'telnet', 'telnetd', 'ftp', 'vsftpd', 'proftpd', 'xinetd', 'rsh', 'rexec', 'smb', 'smbd', 'nmbd', 'nc', 'ncat', 'socat')
    high_risk_ports = {
        '21': 'FTP exposure',
        '22': 'SSH exposure',
        '23': 'Telnet exposure',
        '25': 'SMTP exposure',
        '111': 'rpcbind exposure',
        '139': 'SMB/NetBIOS exposure',
        '445': 'SMB exposure',
        '512': 'rsh exposure',
        '513': 'rlogin exposure',
        '514': 'rexec exposure',
        '3306': 'MySQL exposure',
        '5432': 'PostgreSQL exposure',
        '5900': 'VNC exposure',
        '6379': 'Redis exposure',
        '8080': 'Alternate web/service exposure',
        '8443': 'Alternate TLS web exposure',
        '27017': 'MongoDB exposure',
    }

    for ln in out.splitlines():
        line = ln.strip()
        if not line:
            continue
        if 'LISTEN' not in line and not line.lower().startswith('udp'):
            continue

        m = re.search(r':(\d+)\b', line)
        port = m.group(1) if m else ''
        proc_name = ''
        pid = ''

        mproc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if mproc:
            proc_name = mproc.group(1)
            pid = mproc.group(2)
        else:
            mn = re.search(r'\s(\d+)/([^\s]+)$', line)
            if mn:
                pid = mn.group(1)
                proc_name = mn.group(2)

        if not proc_name and port not in high_risk_ports:
            continue

        owner = ''
        if pid.isdigit():
            pres = run_command(f'ps -o user=,ppid=,args= -p {pid}', shell=True)
            if pres and isinstance(pres, list) and '_output' in pres[0]:
                owner = pres[0]['_output'].strip().split()[0] if pres[0]['_output'].strip() else ''

        risk_hint = high_risk_ports.get(port, 'Listening service/process')
        if proc_name.lower() in suspicious_terms:
            risk_hint = f'Suspicious listener/process family: {proc_name}'

        rows.append({
            'port': port,
            'process': proc_name or 'unknown',
            'pid': pid or 'unknown',
            'user': owner or 'unknown',
            'service_name': proc_name or 'unknown',
            'status': 'listening',
            'severity': _linux_network_exposure_severity(port=port, process_name=proc_name, risk_hint=risk_hint, base='Medium'),
            'risk_hint': risk_hint,
            'evidence': line,
        })

    if not rows:
        rows = [{'status': 'No suspicious network listeners detected'}]
    else:
        sev_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        rows.sort(key=lambda r: sev_rank.get(r.get('severity', 'Info'), 0), reverse=True)
    display_and_export('linux_suspicious_network_listeners_by_process', rows)


def linux_user_accounts_and_group_privileges():
    rows = []

    passwd_out, _ = _run_first_success(['getent passwd', 'cat /etc/passwd'])
    if passwd_out:
        for ln in passwd_out.splitlines():
            parts = ln.split(':')
            if len(parts) < 7:
                continue
            username, uid, gid, gecos, home, shell = parts[0], parts[2], parts[3], parts[4], parts[5], parts[6]
            risk = []
            try:
                uid_num = int(uid)
                if uid_num == 0:
                    risk.append('root user')
                elif uid_num < 1000:
                    risk.append('system/service account')
            except Exception:
                pass
            if shell.strip() in ('/bin/false', '/usr/sbin/nologin', '/sbin/nologin'):
                risk.append('non-login shell')
            rows.append({
                'type': 'user',
                'name': username,
                'uid': uid,
                'gid': gid,
                'home': home,
                'shell': shell,
                'risk_hint': '; '.join(risk),
            })

    groups_out, _ = _run_first_success(['getent group', 'cat /etc/group'])
    if groups_out:
        for ln in groups_out.splitlines():
            parts = ln.split(':')
            if len(parts) < 4:
                continue
            group, gid, members = parts[0], parts[2], parts[3]
            risk = []
            if group in ('sudo', 'wheel', 'adm', 'docker', 'lxd', 'libvirt', 'disk', 'root'):
                risk.append('privileged group')
            rows.append({
                'type': 'group',
                'name': group,
                'uid': '',
                'gid': gid,
                'home': '',
                'shell': '',
                'members': members,
                'risk_hint': '; '.join(risk),
            })

    if not rows:
        rows = [{'status': 'No user/group inventory found'}]
    display_and_export('linux_user_accounts_and_group_privileges', rows)


def linux_recent_executable_writes_execution_correlation():
    rows = []
    recent_execs_out, err = _run_first_success([
        "find /tmp /var/tmp /dev/shm /home -xdev -type f \( -perm -111 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.bin' -o -name '*.run' \) -printf '%TY-%Tm-%Td %TH:%TM:%TS|%p\n' 2>/dev/null | sort -r | head -n 150",
    ])

    if recent_execs_out:
        running_processes_out, _ = _run_first_success(['ps -eo pid,lstart,user,args --sort=-lstart | head -n 200'])
        running_lines = running_processes_out.splitlines() if running_processes_out else []
        for ln in recent_execs_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            ts_path = s.split('|', 1)
            if len(ts_path) != 2:
                continue
            ts, path = ts_path
            filename = Path(path).name.lower()
            exec_hint = ''
            if any(filename.endswith(ext) for ext in ('.sh', '.py', '.pl', '.run', '.bin')):
                exec_hint = 'Potential script/binary dropper'
            if any(marker in filename for marker in ('setup', 'install', 'update', 'tmp', 'cache', 'payload', 'stage')):
                exec_hint = (exec_hint + '; ' if exec_hint else '') + 'Suspicious filename pattern'
            matched_proc = ''
            matched_user = ''
            for pl in running_lines:
                low = pl.lower()
                if filename and filename in low:
                    matched_proc = pl
                    break
            if matched_proc:
                match_parts = re.split(r'\s{2,}', matched_proc.strip(), maxsplit=4)
                if len(match_parts) >= 3:
                    matched_user = match_parts[2]
            rows.append({
                'timestamp': ts,
                'path': path,
                'basename': filename,
                'execution_correlation': matched_proc[:1000],
                'user': matched_user,
                'risk_hint': exec_hint or 'Recent executable write candidate',
            })

    if not rows:
        rows = [{'status': 'No recent executable write candidates found', 'error': err}]
    display_and_export('linux_recent_executable_writes_execution_correlation', rows)


def linux_systemd_unit_anomalies():
    rows = []
    enabled_out, _ = _run_first_success(['systemctl list-unit-files --type=service --no-pager --no-legend'])
    if enabled_out:
        for ln in enabled_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            parts = re.split(r'\s{2,}', s)
            if len(parts) < 2:
                continue
            unit = parts[0]
            state = parts[1]
            risk = []
            if state in ('masked', 'generated', 'static'):
                risk.append('non-standard unit state')
            if any(term in unit.lower() for term in ('debug', 'test', 'sample', 'backup', 'tmp', 'shell', 'reverse', 'payload')):
                risk.append('suspicious unit name')
            rows.append({'unit': unit, 'state': state, 'risk_hint': '; '.join(risk)})

    rc_out, _ = _run_first_success(['ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null'])
    if rc_out:
        for ln in rc_out.splitlines():
            s = ln.strip()
            if s:
                risk = 'unit file or override location'
                if '.service' in s or '.timer' in s or '.socket' in s:
                    risk = 'systemd unit file path'
                rows.append({'unit': s, 'state': '', 'risk_hint': risk})

    if not rows:
        rows = [{'status': 'No systemd unit anomaly data found'}]
    display_and_export('linux_systemd_unit_anomalies', rows)


def linux_login_session_correlation():
    rows = []
    who_out, _ = _run_first_success(['who -a', 'who'])
    last_out, _ = _run_first_success(['last -n 50', 'lastlog | head -n 50'])
    journal_out, _ = _run_first_success([
        "journalctl --no-pager -n 300 | grep -Ei 'session opened for user|session closed for user|Accepted|Failed password|sudo:' | tail -n 200 || true",
        "tail -n 300 /var/log/auth.log 2>/dev/null | grep -Ei 'session opened for user|session closed for user|Accepted|Failed password|sudo:' | tail -n 200 || true",
        "tail -n 300 /var/log/secure 2>/dev/null | grep -Ei 'session opened for user|session closed for user|Accepted|Failed password|sudo:' | tail -n 200 || true",
    ])

    if who_out:
        for ln in who_out.splitlines():
            s = ln.strip()
            if s:
                rows.append({'source': 'who', 'entry': s, 'risk_hint': 'Active login/session record'})

    if last_out:
        for ln in last_out.splitlines():
            s = ln.strip()
            if s:
                rows.append({'source': 'last', 'entry': s, 'risk_hint': 'Historical logon record'})

    if journal_out:
        for ln in journal_out.splitlines():
            s = ln.strip()
            if s:
                hint = 'Authentication/session event'
                if 'failed password' in s.lower() or 'authentication failure' in s.lower():
                    hint = 'Failed auth event'
                rows.append({'source': 'auth_logs', 'entry': s, 'risk_hint': hint})

    if not rows:
        rows = [{'status': 'No login/session correlation data found'}]
    display_and_export('linux_login_session_correlation', rows)


def linux_world_writable_and_suid_scan():
    rows = []
    ww_out, _ = _run_first_success(['find / -xdev -type f -perm -0002 2>/dev/null | head -n 200'])
    if ww_out:
        for ln in ww_out.splitlines():
            if ln.strip():
                rows.append({'category': 'world_writable', 'path': ln.strip(), 'risk_hint': 'World-writable file'})

    suid_out, err = _run_first_success(['find / -xdev -type f -perm -4000 2>/dev/null | head -n 200'])
    if suid_out:
        for ln in suid_out.splitlines():
            if ln.strip():
                rows.append({'category': 'suid', 'path': ln.strip(), 'risk_hint': 'SUID binary; review necessity'})

    if not rows:
        rows = [{'status': 'No world-writable/SUID results found', 'error': err}]
    display_and_export('linux_world_writable_and_suid_scan', rows)


def linux_shell_history_collection():
    rows = []
    hist_out, err = _run_first_success([
        "for f in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do [ -f \"$f\" ] && awk -v src=\"$f\" '{print src \" :: \" $0}' \"$f\" | tail -n 120; done",
    ])
    if hist_out:
        for ln in hist_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            parts = s.split(' :: ', 1)
            rows.append({
                'source': parts[0] if len(parts) > 1 else 'history',
                'entry': parts[1] if len(parts) > 1 else s,
            })

    if not rows:
        rows = [{'status': 'No shell history files found/readable', 'error': err}]
    display_and_export('linux_shell_history_collection', rows)


def linux_process_tree():
    """Linux-native process tree analysis for a chosen PID."""
    pid = console.input('Enter PID: ').strip()
    if not pid.isdigit():
        console.print('[red]Invalid PID[/red]')
        return
    target_pid = int(pid)

    out, err = _run_first_success([
        'ps -eo pid=,ppid=,comm=,args=',
        'ps -eo pid=,ppid=,comm=',
    ])
    if not out:
        console.print(f'[red]Unable to read process list: {err}[/red]')
        return

    proc_map = {}
    for ln in out.splitlines():
        s = ln.strip()
        if not s:
            continue
        parts = s.split(None, 3)
        if len(parts) < 3:
            continue
        try:
            pid_val = int(parts[0])
            ppid_val = int(parts[1])
        except Exception:
            continue
        name = parts[2]
        cmdline = parts[3] if len(parts) > 3 else name
        proc_map[pid_val] = {
            'ppid': ppid_val,
            'name': name,
            'cmdline': cmdline,
        }

    if target_pid not in proc_map:
        console.print(f'[yellow]Wrong PID: process {target_pid} not found.[/yellow]')
        return

    # Build ancestry chain up to init/root parent.
    ancestry = []
    current = target_pid
    visited = set()
    while current in proc_map and current not in visited:
        visited.add(current)
        entry = proc_map[current]
        ancestry.append((current, entry['name']))
        parent = entry['ppid']
        if parent <= 0 or parent == current:
            break
        current = parent

    if ancestry:
        console.print('Process ancestry:')
        for p, name in reversed(ancestry):
            console.print(f'  {p}: {name}')

    # Build children index for subtree expansion.
    children = {}
    for cpid, entry in proc_map.items():
        ppid = entry['ppid']
        children.setdefault(ppid, []).append(cpid)
    for ppid in children:
        children[ppid].sort()

    def _render_subtree(root_pid, depth=0, seen=None):
        if seen is None:
            seen = set()
        if root_pid in seen:
            return []
        seen.add(root_pid)
        entry = proc_map.get(root_pid)
        if not entry:
            return []
        lines = [f"{'  ' * depth}{root_pid}: {entry['name']} ({entry['cmdline'][:140]})"]
        for child_pid in children.get(root_pid, []):
            lines.extend(_render_subtree(child_pid, depth + 1, seen))
        return lines

    subtree = _render_subtree(target_pid)
    if subtree:
        console.print('\nProcess subtree:')
        console.print('\n'.join(subtree))


def linux_file_metadata():
    """Linux wrapper for interactive file metadata analysis."""
    file_details()


def _linux_isolate_host_safe_mode(ir_dry_run=False):
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    backend = _linux_detect_firewall_backend()
    if not backend:
        console.print('[red]No supported firewall backend detected (iptables/nft/ufw/firewall-cmd).[/red]')
        return

    rollback_file = outdir / f'linux_ir_firewall_rollback_{ts}.sh'
    marker_file = outdir / 'linux_ir_last_rollback_path.txt'

    if backend == 'iptables':
        backup = outdir / f'iptables_backup_{ts}.rules'
        cmds = [
            f'iptables-save > {shlex.quote(str(backup))}',
            'iptables -P INPUT DROP',
            'iptables -P FORWARD DROP',
            'iptables -P OUTPUT DROP',
            'iptables -A INPUT -i lo -j ACCEPT',
            'iptables -A OUTPUT -o lo -j ACCEPT',
            'iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
            'iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
        ]
        rollback_cmds = [f'iptables-restore < {shlex.quote(str(backup))}']
    elif backend == 'nft':
        backup = outdir / f'nft_backup_{ts}.conf'
        cmds = [
            f'nft list ruleset > {shlex.quote(str(backup))}',
            'nft flush ruleset',
            'nft add table inet filter',
            'nft add chain inet filter input { type filter hook input priority 0; policy drop; }',
            'nft add chain inet filter output { type filter hook output priority 0; policy drop; }',
            'nft add chain inet filter forward { type filter hook forward priority 0; policy drop; }',
            'nft add rule inet filter input iif lo accept',
            'nft add rule inet filter output oif lo accept',
            'nft add rule inet filter input ct state established,related accept',
            'nft add rule inet filter output ct state established,related accept',
        ]
        rollback_cmds = [f'nft -f {shlex.quote(str(backup))}']
    elif backend == 'ufw':
        backup = outdir / f'ufw_backup_{ts}.txt'
        cmds = [
            f'ufw status verbose > {shlex.quote(str(backup))}',
            'ufw --force default deny incoming',
            'ufw --force default deny outgoing',
            'ufw --force enable',
        ]
        rollback_cmds = [
            'ufw --force default deny incoming',
            'ufw --force default allow outgoing',
            'ufw --force reload',
        ]
    else:
        backup = outdir / f'firewalld_backup_{ts}.txt'
        cmds = [
            f'firewall-cmd --list-all-zones > {shlex.quote(str(backup))}',
            'firewall-cmd --set-default-zone=drop',
            'firewall-cmd --runtime-to-permanent',
        ]
        rollback_cmds = ['firewall-cmd --set-default-zone=public', 'firewall-cmd --runtime-to-permanent']

    if ir_dry_run:
        _print_ir_dry_run(
            f'Linux safe-mode host isolation ({backend})',
            details={'rollback_file': str(rollback_file), 'backup': str(backup)},
            commands=cmds,
        )
        return

    failed = []
    for c in cmds:
        res = run_command(c, shell=True)
        if res and isinstance(res, list) and '_error' in res[0]:
            failed.append(f"{c} :: {res[0]['_error']}")

    rollback_file.write_text('#!/bin/sh\n' + '\n'.join(rollback_cmds) + '\n', encoding='utf-8')
    run_command(f'chmod +x {shlex.quote(str(rollback_file))}', shell=True)
    marker_file.write_text(str(rollback_file), encoding='utf-8')

    if failed:
        console.print('[yellow]Isolation attempted with warnings:[/yellow]')
        for f in failed:
            console.print(f'  - {f}')
    else:
        console.print(f'[green]Safe-mode isolation applied using {backend}.[/green]')
    console.print('[cyan]Isolation execution summary:[/cyan]')
    console.print(f'  - Backend: {backend}')
    console.print(f'  - Backup snapshot: {backup}')
    console.print('  - Network effect: default deny for inbound/outbound, loopback and established traffic allowed (where applicable)')
    console.print('  - Recovery: run the rollback script to restore previous firewall state/policy')
    console.print(f'[cyan]Rollback script saved:[/cyan] {rollback_file}')


def _linux_run_last_isolation_rollback(ir_dry_run=False):
    marker_file = Path('outputs') / 'linux_ir_last_rollback_path.txt'
    if not marker_file.exists():
        console.print('[yellow]No rollback marker found. Run isolation first.[/yellow]')
        return
    rollback_path = marker_file.read_text(encoding='utf-8').strip()
    if not rollback_path:
        console.print('[yellow]Rollback marker is empty.[/yellow]')
        return

    cmd = f'sh {shlex.quote(rollback_path)}'
    if ir_dry_run:
        _print_ir_dry_run('Rollback Linux safe-mode isolation', commands=[cmd])
        return

    res = run_command(cmd, shell=True)
    if res and isinstance(res, list) and '_error' in res[0]:
        console.print(f"[red]Rollback failed: {res[0]['_error']}[/red]")
    else:
        console.print(f'[green]Rollback command executed from {rollback_path}[/green]')
        console.print('[cyan]Rollback execution summary:[/cyan]')
        console.print('  - Restored firewall state/policy from saved backup commands')
        console.print('  - Isolation default-deny posture has been reverted')
        console.print('  - Re-check network exposure and firewall rules to confirm expected state')


def _linux_remove_service_definition(ir_dry_run=False):
    """Remove a Linux service definition safely (best effort) after stopping/disabling it."""
    svc_input = console.input('Service name/unit to remove (e.g., mysvc or mysvc.service): ').strip()
    if not svc_input:
        console.print('[red]No service name entered[/red]')
        return

    svc_unit = svc_input if svc_input.endswith(('.service', '.socket')) else f'{svc_input}.service'
    stop_disable_cmds = [
        f'systemctl stop {svc_unit}',
        f'systemctl disable {svc_unit}',
        f'systemctl mask {svc_unit}',
    ]
    if ir_dry_run:
        _print_ir_dry_run('Remove/delete Linux service', details={'service': svc_unit}, commands=stop_disable_cmds + ['Resolve and remove unit file path'])
        return

    _linux_execute_command_series('Prepare service for removal', stop_disable_cmds, ir_dry_run=False, details={'service': svc_unit})

    frag = run_command(f'systemctl show -p FragmentPath --value {svc_unit}', shell=True)
    frag_path = frag[0].get('_output', '').strip() if frag and isinstance(frag, list) else ''

    removed_file = ''
    if frag_path and frag_path.startswith('/etc/systemd/system/'):
        rm_res = run_command(f'rm -f {shlex.quote(frag_path)}', shell=True)
        if rm_res and isinstance(rm_res, list) and '_error' not in rm_res[0]:
            removed_file = frag_path

    unit_override_dir = f'/etc/systemd/system/{svc_unit}.d'
    run_command(f'if [ -d {shlex.quote(unit_override_dir)} ]; then rm -rf {shlex.quote(unit_override_dir)}; fi', shell=True)
    run_command('systemctl daemon-reload', shell=True)
    run_command(f'systemctl reset-failed {svc_unit} || true', shell=True)

    unit_check = run_command(f'systemctl list-unit-files --no-pager --no-legend | awk "{{print $1}}" | grep -Fx {shlex.quote(svc_unit)} >/dev/null 2>&1 && echo present || echo absent', shell=True)
    status = unit_check[0].get('_output', '').strip().lower() if unit_check and isinstance(unit_check, list) else 'unknown'

    if removed_file:
        console.print(f'[green]Removed custom unit file: {removed_file}[/green]')
    elif frag_path and not frag_path.startswith('/etc/systemd/system/'):
        console.print(f'[yellow]Service unit appears package-managed ({frag_path}). Definition file was not deleted.[/yellow]')
        console.print('[yellow]Use your package manager to uninstall the owning package if full removal is required.[/yellow]')
    else:
        console.print('[yellow]No removable custom unit file was found under /etc/systemd/system.[/yellow]')

    if status == 'absent':
        console.print(f'[green]Service definition no longer listed as unit file: {svc_unit}[/green]')
    elif status == 'present':
        console.print(f'[yellow]Service unit file is still present: {svc_unit}[/yellow]')
    else:
        console.print(f'[yellow]Unable to determine final unit-file status for: {svc_unit}[/yellow]')


def _linux_disable_user_account(username, ir_dry_run=False):
    if not username:
        console.print('[red]No username provided[/red]')
        return
    cmds = [
        f'usermod -L {shlex.quote(username)}',
        f'chage -E 0 {shlex.quote(username)}',
        f'usermod -s /usr/sbin/nologin {shlex.quote(username)}',
    ]
    success = _linux_execute_command_series(
        'Disable Linux user account',
        cmds,
        ir_dry_run=ir_dry_run,
        details={'user': username},
    )
    if success and not ir_dry_run:
        lock_out = run_command(f'passwd -S {shlex.quote(username)}', shell=True)
        shell_out = run_command(f'getent passwd {shlex.quote(username)}', shell=True)
        lock_text = lock_out[0].get('_output', '').strip() if lock_out and isinstance(lock_out, list) else ''
        shell_text = shell_out[0].get('_output', '').strip() if shell_out and isinstance(shell_out, list) else ''
        current_shell = shell_text.split(':')[-1] if ':' in shell_text else 'unknown'
        console.print(f'[green]Account disable/lock commands applied for user: {username}[/green]')
        if lock_text:
            console.print(f'[cyan]Verification:[/cyan] passwd -S => {lock_text}')
        console.print(f'[cyan]Verification:[/cyan] login shell => {current_shell}')


def _linux_enable_user_account(username, ir_dry_run=False):
    if not username:
        console.print('[red]No username provided[/red]')
        return
    shell = console.input('Login shell to restore (default /bin/bash): ').strip() or '/bin/bash'
    cmds = [
        f'usermod -U {shlex.quote(username)}',
        f'chage -E -1 {shlex.quote(username)}',
        f'usermod -s {shlex.quote(shell)} {shlex.quote(username)}',
    ]
    success = _linux_execute_command_series(
        'Enable Linux user account',
        cmds,
        ir_dry_run=ir_dry_run,
        details={'user': username, 'shell': shell},
    )
    if success and not ir_dry_run:
        lock_out = run_command(f'passwd -S {shlex.quote(username)}', shell=True)
        shell_out = run_command(f'getent passwd {shlex.quote(username)}', shell=True)
        lock_text = lock_out[0].get('_output', '').strip() if lock_out and isinstance(lock_out, list) else ''
        shell_text = shell_out[0].get('_output', '').strip() if shell_out and isinstance(shell_out, list) else ''
        current_shell = shell_text.split(':')[-1] if ':' in shell_text else 'unknown'
        console.print(f'[green]Account enable/unlock commands applied for user: {username}[/green]')
        if lock_text:
            console.print(f'[cyan]Verification:[/cyan] passwd -S => {lock_text}')
        console.print(f'[cyan]Verification:[/cyan] login shell => {current_shell}')


def _linux_add_user_account(username, ir_dry_run=False):
    if not username:
        console.print('[red]No username provided[/red]')
        return
    shell = console.input('Login shell (default /bin/bash): ').strip() or '/bin/bash'
    password = console.input('Password (leave blank to keep account locked/unset): ').strip()
    cmds = [
        f'useradd -m -s {shlex.quote(shell)} {shlex.quote(username)}',
        f'adduser --disabled-password --gecos "" {shlex.quote(username)}',
    ]
    success = _linux_execute_command_candidates(
        'Add Linux user account',
        cmds,
        ir_dry_run=ir_dry_run,
        details={'user': username, 'shell': shell},
    )
    if not success:
        return

    if password:
        setpw_cmd = f'echo {shlex.quote(f"{username}:{password}")} | chpasswd'
        if ir_dry_run:
            _print_ir_dry_run('Set Linux user password', details={'user': username}, commands=[setpw_cmd])
        else:
            pw_res = run_command(setpw_cmd, shell=True)
            if pw_res and isinstance(pw_res, list) and '_error' in pw_res[0]:
                console.print(f"[yellow]User created, but setting password failed: {pw_res[0]['_error']}[/yellow]")
            else:
                console.print(f'[green]Password set for user: {username}[/green]')

    if not ir_dry_run:
        check = run_command(f'getent passwd {shlex.quote(username)}', shell=True)
        if check and isinstance(check, list) and check[0].get('_output', '').strip():
            console.print(f'[green]User account created: {username}[/green]')
        else:
            console.print(f'[yellow]User creation command ran, but user lookup did not return details: {username}[/yellow]')


def _linux_remove_user_account(username, remove_home=False, ir_dry_run=False):
    if not username:
        console.print('[red]No username provided[/red]')
        return
    cmd = f'userdel -r {shlex.quote(username)}' if remove_home else f'userdel {shlex.quote(username)}'
    success = _linux_execute_command_candidates(
        'Remove Linux user account',
        [cmd],
        ir_dry_run=ir_dry_run,
        details={'user': username, 'remove_home': str(remove_home)},
    )
    if success and not ir_dry_run:
        check = run_command(f'getent passwd {shlex.quote(username)}', shell=True)
        still_exists = check and isinstance(check, list) and check[0].get('_output', '').strip()
        if still_exists:
            console.print(f'[yellow]Remove command ran, but account still appears to exist: {username}[/yellow]')
        else:
            console.print(f'[green]User account removed: {username}[/green]')


def _linux_remove_user_from_group(username, group_name, ir_dry_run=False):
    if not username or not group_name:
        console.print('[red]Username and group are required[/red]')
        return
    cmds = [
        f'gpasswd -d {shlex.quote(username)} {shlex.quote(group_name)}',
        f'deluser {shlex.quote(username)} {shlex.quote(group_name)}',
    ]
    success = _linux_execute_command_candidates(
        'Remove Linux user from group',
        cmds,
        ir_dry_run=ir_dry_run,
        details={'user': username, 'group': group_name},
    )
    if success and not ir_dry_run:
        groups = run_command(f'id -nG {shlex.quote(username)}', shell=True)
        gtxt = groups[0].get('_output', '').strip() if groups and isinstance(groups, list) else ''
        if gtxt and group_name in gtxt.split():
            console.print(f'[yellow]Command ran, but user still appears in group {group_name}: {username}[/yellow]')
        else:
            console.print(f'[green]User removed from group {group_name}: {username}[/green]')


def _linux_list_user_accounts():
    """List Linux user account details from /etc/passwd with account status hints."""
    out, err = _run_first_success([
        'getent passwd',
        'cat /etc/passwd',
    ])
    if not out:
        display_and_export('linux_ir_user_accounts', [{'status': 'Failed', 'error': err or 'Unable to read /etc/passwd'}])
        return

    rows = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s or ':' not in s:
            continue
        parts = s.split(':')
        if len(parts) < 7:
            continue
        username = parts[0]
        uid = parts[2]
        gid = parts[3]
        home = parts[5]
        shell = parts[6]
        account_type = 'system' if uid.isdigit() and int(uid) < 1000 else 'regular'
        rows.append({
            'username': username,
            'uid': uid,
            'gid': gid,
            'home': home,
            'shell': shell,
            'account_type': account_type,
        })

    if not rows:
        rows = [{'status': 'No user account rows parsed from /etc/passwd'}]

    regular_rows = [row for row in rows if row.get('account_type') == 'regular']
    system_rows = [row for row in rows if row.get('account_type') == 'system']

    def _print_section(title, section_rows):
        console.print(f'\n[bold cyan]{title}[/bold cyan]')
        if not section_rows:
            console.print('[yellow]No rows in this section.[/yellow]')
            return
        preview = console.input('Rows to preview for this section (default 20, enter 0 for all): ')
        try:
            n = int(preview)
        except Exception:
            n = 20
        table_rows = section_rows if n == 0 else section_rows[:n]
        console.print(json_to_table(table_rows))

    _print_section('Human / regular users', regular_rows)
    _print_section('System accounts', system_rows)

    console.print('\nExport options:')
    console.print('1. CSV  2. JSON  3. XLSX  4. PDF  5. Skip')
    choice = console.input('Choose export format (1-5): ')
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = outdir / f'linux_ir_user_accounts_{ts}'
    if choice == '1':
        export_dataframe(rows, fname.with_suffix('.csv'))
        console.print(f"Saved {fname.with_suffix('.csv')}")
    elif choice == '2':
        export_dataframe(rows, fname.with_suffix('.json'))
        console.print(f"Saved {fname.with_suffix('.json')}")
    elif choice == '3':
        export_dataframe(rows, fname.with_suffix('.xlsx'))
        console.print(f"Saved {fname.with_suffix('.xlsx')}")
    elif choice == '4':
        export_dataframe(rows, fname.with_suffix('.pdf'))
        console.print(f"Saved {fname.with_suffix('.pdf')}")
    else:
        console.print('Skipping export')


def _linux_user_management_menu(ir_dry_run=False):
    while True:
        console.print('\n[bold cyan]User management[/bold cyan]')
        console.print('1. List available users details')
        console.print('2. Disable/lock user account')
        console.print('3. Enable/unlock user account')
        console.print('4. Add user account')
        console.print('5. Remove user account')
        console.print('6. Remove user from group')
        console.print('7. Back')
        sub = console.input('Choose (1-7): ').strip()

        if sub == '1':
            _linux_list_user_accounts()
        elif sub == '2':
            user = console.input('Username to disable/lock: ').strip()
            _linux_disable_user_account(user, ir_dry_run=ir_dry_run)
        elif sub == '3':
            user = console.input('Username to enable/unlock: ').strip()
            _linux_enable_user_account(user, ir_dry_run=ir_dry_run)
        elif sub == '4':
            user = console.input('Username to add: ').strip()
            _linux_add_user_account(user, ir_dry_run=ir_dry_run)
        elif sub == '5':
            user = console.input('Username to remove: ').strip()
            remove_home = console.input('Remove home directory too? (y/N): ').strip().lower() == 'y'
            _linux_remove_user_account(user, remove_home=remove_home, ir_dry_run=ir_dry_run)
        elif sub == '6':
            user = console.input('Username: ').strip()
            group_name = console.input('Group to remove user from: ').strip()
            _linux_remove_user_from_group(user, group_name, ir_dry_run=ir_dry_run)
        elif sub == '7':
            break
        else:
            console.print('[yellow]Invalid choice[/yellow]')


def _linux_remove_cron_entry(ir_dry_run=False):
    target_user = console.input('User for cron cleanup (blank for current user): ').strip()
    if target_user:
        list_cmd = f'crontab -u {shlex.quote(target_user)} -l'
        backup_prefix = f'cron_backup_{target_user}'
    else:
        list_cmd = 'crontab -l'
        backup_prefix = 'cron_backup_current_user'

    listed = run_command(list_cmd, shell=True)
    if not listed or not isinstance(listed, list) or '_output' not in listed[0] or not listed[0]['_output'].strip():
        err = listed[0].get('_error', 'No cron entries found') if listed and isinstance(listed, list) else 'No cron entries found'
        console.print(f'[yellow]{err}[/yellow]')
        return

    lines = [ln for ln in listed[0]['_output'].splitlines() if ln.strip()]
    console.print('[cyan]Current cron entries:[/cyan]')
    for i, ln in enumerate(lines, 1):
        console.print(f'{i}. {ln}')

    idx = console.input('Select line number to remove: ').strip()
    if not idx.isdigit() or int(idx) < 1 or int(idx) > len(lines):
        console.print('[red]Invalid selection[/red]')
        return
    target_line = lines[int(idx) - 1]

    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    backup_file = outdir / f"{backup_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    backup_cmd = f'{list_cmd} > {shlex.quote(str(backup_file))}'
    remove_cmd = f"{list_cmd} | grep -F -v -- {shlex.quote(target_line)} | "
    if target_user:
        remove_cmd += f"crontab -u {shlex.quote(target_user)} -"
    else:
        remove_cmd += 'crontab -'

    if ir_dry_run:
        _print_ir_dry_run(
            'Remove suspicious cron entry',
            details={'user': target_user or 'current', 'entry': target_line, 'backup': str(backup_file)},
            commands=[backup_cmd, remove_cmd],
        )
        return

    run_command(backup_cmd, shell=True)
    res = run_command(remove_cmd, shell=True)
    if res and isinstance(res, list) and '_error' in res[0]:
        console.print(f"[red]Cron cleanup failed: {res[0]['_error']}[/red]")
    else:
        console.print(f'[green]Cron entry removed. Backup saved to {backup_file}[/green]')


def _linux_kill_by_port(ir_dry_run=False):
    port = console.input('Port to terminate bound process(es): ').strip()
    if not port.isdigit():
        console.print('[red]Invalid port[/red]')
        return

    out, err = _run_first_success(['ss -ltnup', 'netstat -tulpn'])
    if not out:
        console.print(f'[red]Unable to inspect sockets: {err}[/red]')
        return

    pids = set()
    evid = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s or f':{port}' not in s:
            continue
        evid.append(s)
        for m in re.findall(r'pid=(\d+)', s):
            pids.add(m)
        mnet = re.search(r'\s(\d+)/[^\s]+$', s)
        if mnet:
            pids.add(mnet.group(1))

    if not pids:
        console.print('[yellow]No PID found for that port in current snapshot.[/yellow]')
        return

    cmds = [f'kill -9 {pid}' for pid in sorted(pids)]
    if ir_dry_run:
        _print_ir_dry_run('Kill process(es) by port', details={'port': port, 'evidence': '; '.join(evid[:5])}, commands=cmds)
        return

    failed = []
    for c in cmds:
        res = run_command(c, shell=True)
        if res and isinstance(res, list) and '_error' in res[0]:
            failed.append(f"{c}: {res[0]['_error']}")
    if failed:
        console.print('[yellow]Kill-by-port completed with warnings:[/yellow]')
        for f in failed:
            console.print(f'  - {f}')
    else:
        console.print(f'[green]Terminated processes on port {port}: {", ".join(sorted(pids))}[/green]')


def _linux_quarantine_file(ir_dry_run=False):
    path = console.input('File path to quarantine: ').strip()
    if not path:
        console.print('[red]No file path provided[/red]')
        return
    p = Path(path)
    if not p.exists() or not p.is_file():
        console.print('[red]File not found[/red]')
        return

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    qdir = Path('outputs') / 'quarantine'
    qdir.mkdir(parents=True, exist_ok=True)
    qpath = qdir / f'{ts}_{p.name}'
    log_path = qdir / 'quarantine_log.jsonl'

    digest = ''
    size = 0
    try:
        data = p.read_bytes()
        size = len(data)
        digest = hashlib.sha256(data).hexdigest()
    except Exception:
        pass

    if ir_dry_run:
        _print_ir_dry_run(
            'Quarantine suspicious file',
            details={'source': str(p), 'destination': str(qpath), 'sha256': digest, 'size': size},
            commands=[f'mv {shlex.quote(str(p))} {shlex.quote(str(qpath))}'],
        )
        return

    res = run_command(f'mv {shlex.quote(str(p))} {shlex.quote(str(qpath))}', shell=True)
    if res and isinstance(res, list) and '_error' in res[0]:
        console.print(f"[red]Quarantine move failed: {res[0]['_error']}[/red]")
        return

    record = {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'source_path': str(p),
        'quarantine_path': str(qpath),
        'sha256': digest,
        'size': size,
    }
    with log_path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(record) + '\n')

    console.print(f'[green]File quarantined:[/green] {qpath}')
    console.print(f'[cyan]Metadata logged:[/cyan] {log_path}')


def _linux_restore_quarantined_file(ir_dry_run=False):
    qdir = Path('outputs') / 'quarantine'
    log_path = qdir / 'quarantine_log.jsonl'
    if not qdir.exists():
        console.print('[yellow]No quarantine directory found.[/yellow]')
        return

    files = []
    try:
        for p in sorted(qdir.iterdir()):
            if p.is_file() and p.name != 'quarantine_log.jsonl':
                files.append(p)
    except Exception as e:
        console.print(f'[red]Failed to read quarantine directory: {e}[/red]')
        return

    if not files:
        console.print('[yellow]No quarantined files available to restore.[/yellow]')
        return

    log_map = {}
    if log_path.exists():
        try:
            for ln in log_path.read_text(encoding='utf-8', errors='ignore').splitlines():
                if not ln.strip():
                    continue
                rec = json.loads(ln)
                qpath = rec.get('quarantine_path', '')
                src = rec.get('source_path', '')
                if qpath:
                    log_map[qpath] = src
                if qpath:
                    log_map[Path(qpath).name] = src
        except Exception:
            pass

    console.print('[cyan]Quarantined files:[/cyan]')
    for i, p in enumerate(files, 1):
        default_restore = log_map.get(str(p), log_map.get(p.name, ''))
        hint = f' -> original: {default_restore}' if default_restore else ''
        console.print(f'{i}. {p}{hint}')

    pick = console.input('Select file number to restore: ').strip()
    if not pick.isdigit() or int(pick) < 1 or int(pick) > len(files):
        console.print('[red]Invalid selection[/red]')
        return

    chosen = files[int(pick) - 1]
    default_dest = log_map.get(str(chosen), log_map.get(chosen.name, ''))
    prompt = 'Restore destination path'
    if default_dest:
        prompt += f' (default {default_dest})'
    prompt += ': '
    dest_input = console.input(prompt).strip()
    dest_path = Path(dest_input) if dest_input else (Path(default_dest) if default_dest else None)
    if not dest_path:
        console.print('[red]No destination provided and no logged original path available.[/red]')
        return

    if dest_path.exists():
        overwrite = console.input(f'Destination exists ({dest_path}). Overwrite? (y/N): ').strip().lower() == 'y'
        if not overwrite:
            alt = dest_path.with_name(dest_path.name + f'.restored_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
            console.print(f'[yellow]Using alternate destination:[/yellow] {alt}')
            dest_path = alt

    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        console.print(f'[red]Failed to prepare destination directory: {e}[/red]')
        return

    cmd = f'mv {shlex.quote(str(chosen))} {shlex.quote(str(dest_path))}'
    if ir_dry_run:
        _print_ir_dry_run(
            'Restore quarantined file',
            details={'source': str(chosen), 'destination': str(dest_path)},
            commands=[cmd],
        )
        return

    res = run_command(cmd, shell=True)
    if res and isinstance(res, list) and '_error' in res[0]:
        console.print(f"[red]Restore failed: {res[0]['_error']}[/red]")
        return

    console.print(f'[green]Restored file:[/green] {dest_path}')


def linux_system_context():
    rows = []
    host = run_command('hostname', shell=True)
    uname = run_command('uname -srmo', shell=True)
    uptime = run_command('uptime -p', shell=True)
    distro = run_command('cat /etc/os-release', shell=True)
    user = run_command('whoami', shell=True)
    tz = run_command('timedatectl show -p Timezone --value', shell=True)
    boot = run_command('uptime -s', shell=True)
    ipaddr = run_command('hostname -I', shell=True)
    cpu = run_command("awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo", shell=True)
    mem = run_command("awk '/MemTotal/ {print $2 \" kB\"}' /proc/meminfo", shell=True)

    row = {
        'hostname': host[0].get('_output', '') if host and isinstance(host, list) else '',
        'kernel': uname[0].get('_output', '') if uname and isinstance(uname, list) else '',
        'uptime': uptime[0].get('_output', '') if uptime and isinstance(uptime, list) else '',
        'current_user': user[0].get('_output', '') if user and isinstance(user, list) else '',
        'timezone': tz[0].get('_output', '') if tz and isinstance(tz, list) else '',
        'boot_time': boot[0].get('_output', '') if boot and isinstance(boot, list) else '',
        'ip_addresses': ipaddr[0].get('_output', '') if ipaddr and isinstance(ipaddr, list) else '',
        'cpu_model': cpu[0].get('_output', '').strip() if cpu and isinstance(cpu, list) else '',
        'memory_total': mem[0].get('_output', '').strip() if mem and isinstance(mem, list) else '',
    }
    if distro and isinstance(distro, list) and '_output' in distro[0]:
        for ln in distro[0]['_output'].splitlines():
            if ln.startswith('PRETTY_NAME='):
                row['distro'] = ln.split('=', 1)[1].strip().strip('"')
                break
    rows.append(row)
    display_and_export('linux_system_context', rows)


def linux_process_snapshot():
    out, err = _run_first_success([
        "ps -eo pid,ppid,user,comm,args --sort=-pid | head -n 300",
        "ps aux | head -n 300",
    ])
    if out:
        display_and_export('linux_process_snapshot', _rows_from_lines('process', out.splitlines(), field='process'))
    else:
        display_and_export('linux_process_snapshot', [{'status': 'Failed', 'error': err}])


def linux_logged_in_users():
    out, err = _run_first_success(['who', 'w -h'])
    if out:
        display_and_export('linux_logged_in_users', _rows_from_lines('session', out.splitlines(), field='session'))
    else:
        display_and_export('linux_logged_in_users', [{'status': 'Failed', 'error': err}])


def linux_listening_ports():
    out, err = _run_first_success([
        'ss -tulpn',
        'netstat -tulpn',
    ])
    if out:
        display_and_export('linux_listening_ports', _rows_from_lines('listening', out.splitlines(), field='listening'))
    else:
        display_and_export('linux_listening_ports', [{'status': 'Failed', 'error': err}])


def linux_network_connections():
    out, err = _run_first_success([
        'ss -tunap',
        'netstat -tunap',
    ])
    if out:
        display_and_export('linux_network_connections', _rows_from_lines('connection', out.splitlines(), field='connection'))
    else:
        display_and_export('linux_network_connections', [{'status': 'Failed', 'error': err}])


def _linux_parse_iptables_rule_line(line, backend='iptables'):
    s = (line or '').strip()
    if not s.startswith('-A '):
        return None
    parts = s.split()
    if len(parts) < 2:
        return None

    chain = parts[1]

    def _value(flag):
        if flag in parts:
            i = parts.index(flag)
            if i + 1 < len(parts):
                return parts[i + 1]
        return ''

    action = _value('-j').upper()
    proto = _value('-p')
    src = _value('-s')
    dst = _value('-d')
    dport = _value('--dport')
    sport = _value('--sport')

    return {
        'backend': backend,
        'table': 'filter',
        'chain': chain,
        'action': action,
        'protocol': proto,
        'source': src,
        'destination': dst,
        'dport': dport,
        'sport': sport,
        'direction': 'inbound' if chain.upper() == 'INPUT' else ('outbound' if chain.upper() == 'OUTPUT' else ''),
        'rule': s,
    }


def _linux_parse_nft_ruleset_lines(lines):
    rows = []
    table_name = ''
    chain_name = ''

    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith('table '):
            table_name = s.split(None, 2)[2] if len(s.split(None, 2)) >= 3 else s
            continue
        if s.startswith('chain '):
            chain_name = s.split()[1] if len(s.split()) >= 2 else ''
            continue
        if s in ('{', '}'):
            continue

        action = ''
        for token in ('accept', 'drop', 'reject', 'queue'):
            if re.search(rf'\b{token}\b', s):
                action = token.upper()
                break

        proto = ''
        for token in ('tcp', 'udp', 'icmp', 'icmpv6', 'ip', 'ip6'):
            if re.search(rf'\b{token}\b', s):
                proto = token
                break

        src_m = re.search(r'\bsaddr\s+([^\s]+)', s)
        dst_m = re.search(r'\bdaddr\s+([^\s]+)', s)
        dport_m = re.search(r'\bdport\s+([^\s]+)', s)
        sport_m = re.search(r'\bsport\s+([^\s]+)', s)

        rows.append({
            'backend': 'nftables',
            'table': table_name,
            'chain': chain_name,
            'action': action,
            'protocol': proto,
            'source': src_m.group(1) if src_m else '',
            'destination': dst_m.group(1) if dst_m else '',
            'dport': dport_m.group(1) if dport_m else '',
            'sport': sport_m.group(1) if sport_m else '',
            'direction': 'inbound' if chain_name.lower() == 'input' else ('outbound' if chain_name.lower() == 'output' else ''),
            'rule': s,
        })

    return rows


def _linux_parse_ufw_status_line(line):
    s = (line or '').strip()
    if not s:
        return None
    if s.lower().startswith(('status:', 'to ', '--', 'logging:', 'default:')):
        return None

    m = re.match(r'^\[\s*\d+\]\s+(.+?)\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)\s+(.+)$', s, flags=re.IGNORECASE)
    if not m:
        return {
            'backend': 'ufw', 'table': '', 'chain': '', 'action': '', 'protocol': '',
            'source': '', 'destination': '', 'dport': '', 'sport': '', 'direction': '', 'rule': s,
        }

    to_field, action, direction, src_field = m.groups()
    proto = ''
    dport = ''
    proto_m = re.search(r'/(tcp|udp)\b', to_field, flags=re.IGNORECASE)
    if proto_m:
        proto = proto_m.group(1).lower()
    port_m = re.search(r'^(\d+)', to_field)
    if port_m:
        dport = port_m.group(1)

    return {
        'backend': 'ufw',
        'table': '',
        'chain': '',
        'action': action.upper(),
        'protocol': proto,
        'source': src_field,
        'destination': to_field,
        'dport': dport,
        'sport': '',
        'direction': direction.lower(),
        'rule': s,
    }


def _linux_parse_firewalld_line(line, current_zone=''):
    s = (line or '').strip()
    if not s:
        return None, current_zone

    zone_m = re.match(r'^([\w-]+)\s+\(active\)$', s)
    if zone_m:
        return None, zone_m.group(1)

    if ':' not in s:
        return {
            'backend': 'firewalld', 'table': '', 'chain': current_zone, 'action': '', 'protocol': '',
            'source': '', 'destination': '', 'dport': '', 'sport': '', 'direction': '', 'rule': s,
        }, current_zone

    key, val = s.split(':', 1)
    key = key.strip()
    val = val.strip()
    return {
        'backend': 'firewalld',
        'table': '',
        'chain': current_zone,
        'action': key,
        'protocol': '',
        'source': '',
        'destination': '',
        'dport': '',
        'sport': '',
        'direction': '',
        'rule': f'{key}: {val}',
    }, current_zone


def _linux_is_drop_like_rule(row):
    action = str(row.get('action', '')).lower()
    rule = str(row.get('rule', '')).lower()
    return action in ('drop', 'deny', 'reject') or any(tok in rule for tok in (' drop', ' deny', ' reject'))


def _linux_firewall_ip_matches(ip, direction=''):
    """Return matching firewall rows for an IP and optional direction filter."""
    ip = str(ip or '').strip()
    if not ip:
        return []

    wanted_direction = str(direction or '').lower().strip()
    rows = _linux_collect_firewall_rules_rows()
    matches = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get('status') == 'error':
            continue

        rdir = str(row.get('direction', '')).lower()
        src = str(row.get('source', ''))
        dst = str(row.get('destination', ''))
        raw = str(row.get('rule', ''))

        contains_ip = ip in src or ip in dst or ip in raw
        if not contains_ip:
            continue

        if wanted_direction and rdir and rdir != wanted_direction:
            continue
        if wanted_direction and not rdir:
            # Keep potentially relevant rows when parser couldn't infer direction.
            if wanted_direction == 'inbound' and ip not in src and ip not in raw:
                continue
            if wanted_direction == 'outbound' and ip not in dst and ip not in raw:
                continue

        matches.append(row)
    return matches


def _linux_expand_service_candidates(service_candidates):
    """Expand service candidates using discovered unit files and common naming variants."""
    expanded = list(service_candidates)

    # Add common suffix variants explicitly.
    for svc in list(expanded):
        if not svc.endswith('.service') and not svc.endswith('.socket'):
            expanded.append(f'{svc}.service')
            expanded.append(f'{svc}.socket')

    # Discover similar units from systemd unit files.
    if _linux_has_command('systemctl'):
        out, _ = _run_first_success([
            'systemctl list-unit-files --type=service --type=socket --no-pager --no-legend',
            'systemctl list-unit-files --no-pager --no-legend',
        ])
        if out:
            unit_names = []
            for ln in out.splitlines():
                s = ln.strip()
                if not s:
                    continue
                unit = s.split()[0]
                if unit:
                    unit_names.append(unit)

            roots = set()
            for svc in service_candidates:
                base = svc.replace('.service', '').replace('.socket', '')
                if base:
                    roots.add(base)

            for unit in unit_names:
                lower = unit.lower()
                for root in roots:
                    if root.lower() in lower:
                        expanded.append(unit)
                        break

    # de-duplicate while preserving order
    seen = set()
    unique = []
    for svc in expanded:
        if svc in seen:
            continue
        seen.add(svc)
        unique.append(svc)
    return unique


def _linux_collect_firewall_rules_rows():
    """Collect Linux firewall rules from available backend(s)."""
    rows = []

    # iptables / ip6tables
    if _linux_has_command('iptables'):
        out, err = _run_first_success(['iptables -S', 'iptables -L -n -v'])
        if out:
            for ln in out.splitlines():
                s = ln.strip()
                if s:
                    parsed = _linux_parse_iptables_rule_line(s, backend='iptables')
                    if parsed:
                        rows.append(parsed)
                    else:
                        rows.append({
                            'backend': 'iptables', 'table': '', 'chain': '', 'action': '', 'protocol': '',
                            'source': '', 'destination': '', 'dport': '', 'sport': '', 'direction': '', 'rule': s,
                        })
        elif err:
            rows.append({'backend': 'iptables', 'status': 'error', 'error': err})

    if _linux_has_command('ip6tables'):
        out, err = _run_first_success(['ip6tables -S', 'ip6tables -L -n -v'])
        if out:
            for ln in out.splitlines():
                s = ln.strip()
                if s:
                    parsed = _linux_parse_iptables_rule_line(s, backend='ip6tables')
                    if parsed:
                        rows.append(parsed)
                    else:
                        rows.append({
                            'backend': 'ip6tables', 'table': '', 'chain': '', 'action': '', 'protocol': '',
                            'source': '', 'destination': '', 'dport': '', 'sport': '', 'direction': '', 'rule': s,
                        })
        elif err:
            rows.append({'backend': 'ip6tables', 'status': 'error', 'error': err})

    # nftables
    if _linux_has_command('nft'):
        out, err = _run_first_success(['nft list ruleset'])
        if out:
            rows.extend(_linux_parse_nft_ruleset_lines(out.splitlines()))
        elif err:
            rows.append({'backend': 'nftables', 'status': 'error', 'error': err})

    # ufw
    if _linux_has_command('ufw'):
        out, err = _run_first_success(['ufw status numbered', 'ufw status verbose'])
        if out:
            for ln in out.splitlines():
                parsed = _linux_parse_ufw_status_line(ln)
                if parsed:
                    rows.append(parsed)
        elif err:
            rows.append({'backend': 'ufw', 'status': 'error', 'error': err})

    # firewalld
    if _linux_has_command('firewall-cmd'):
        out, err = _run_first_success(['firewall-cmd --list-all-zones'])
        if out:
            zone = ''
            for ln in out.splitlines():
                parsed, zone = _linux_parse_firewalld_line(ln, zone)
                if parsed:
                    rows.append(parsed)
        elif err:
            rows.append({'backend': 'firewalld', 'status': 'error', 'error': err})

    return rows


def linux_firewall_rules_snapshot():
    """List current Linux firewall rules across available backend(s)."""
    rows = _linux_collect_firewall_rules_rows()
    if not rows:
        rows = [{'status': 'No supported firewall backend detected (iptables/nft/ufw/firewall-cmd)'}]
    display_and_export('linux_firewall_rules_snapshot', rows)


def linux_services_snapshot():
    out, err = _run_first_success([
        'systemctl list-units --type=service --all --no-pager --no-legend | head -n 300',
        'service --status-all',
    ])
    if out:
        display_and_export('linux_services_snapshot', _rows_from_lines('service', out.splitlines(), field='service'))
    else:
        display_and_export('linux_services_snapshot', [{'status': 'Failed', 'error': err}])


def linux_startup_persistence():
    rows = []
    cron_user = run_command('crontab -l', shell=True)
    if cron_user and isinstance(cron_user, list) and '_output' in cron_user[0] and cron_user[0]['_output'].strip():
        rows.append({'source': 'user_crontab', 'content': cron_user[0]['_output'][:3000]})

    cron_dirs = run_command('ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly', shell=True)
    if cron_dirs and isinstance(cron_dirs, list) and '_output' in cron_dirs[0] and cron_dirs[0]['_output'].strip():
        rows.append({'source': 'cron_directories', 'content': cron_dirs[0]['_output'][:3000]})

    systemd = run_command('systemctl list-unit-files --type=service --no-pager | head -n 300', shell=True)
    if systemd and isinstance(systemd, list) and '_output' in systemd[0] and systemd[0]['_output'].strip():
        rows.append({'source': 'systemd_unit_files', 'content': systemd[0]['_output'][:3000]})

    if not rows:
        rows = [{'status': 'No startup persistence snapshot data found'}]
    display_and_export('linux_startup_persistence', rows)


def linux_auth_events_recent():
    out, err = _run_first_success([
        'tail -n 200 /var/log/auth.log',
        'tail -n 200 /var/log/secure',
        "journalctl -u ssh -u sshd -u sudo --no-pager -n 200",
    ])
    if out:
        display_and_export('linux_auth_events_recent', _rows_from_lines('auth_event', out.splitlines(), field='auth_event'))
    else:
        display_and_export('linux_auth_events_recent', [{'status': 'Failed', 'error': err}])


def _mac_rows_from_command(artifact_name, commands, field='line', fallback_status='No data collected'):
    out, err = _run_first_success(commands)
    if out:
        rows = _rows_from_lines(artifact_name, out.splitlines(), field=field)
    else:
        row = {'status': fallback_status}
        # Keep diagnostic context only for unexpected command failures.
        if err and 'returncode 1' not in err.lower() and 'return code 1' not in err.lower():
            row['note'] = err
        rows = [row]
    display_and_export(artifact_name, rows)


def _mac_get_listening_ports():
    out, _ = _run_first_success(['lsof -nP -iTCP -sTCP:LISTEN', 'netstat -anv -p tcp'])
    ports = set()
    if not out:
        return ports
    for ln in out.splitlines():
        m = re.search(r':(\d+)\b', ln)
        if m:
            ports.add(m.group(1))
    return ports


def _mac_service_state(label_candidates):
    for label in label_candidates:
        ac_out, ac_err = _run_shell_command_timeout(f'launchctl print system/{label} 2>&1', timeout_sec=10)
        combined = f'{ac_out}\n{ac_err}'.lower()
        if 'could not find service' in combined or 'service not found' in combined:
            return label, 'absent', 'absent'

        en = run_command(f'launchctl print-disabled system | grep -F "\"{label}\"" >/dev/null 2>&1 && echo disabled || echo enabled_or_unknown', shell=True)
        enabled = en[0].get('_output', '').strip() if en and isinstance(en, list) else 'unknown'
        active = 'loaded' if ac_out.strip() else 'unloaded'
        if enabled or active:
            return label, enabled, active
    return '', 'unknown', 'unknown'


def _mac_service_label_exists(label):
    loaded_out, _ = _run_shell_command_timeout(f'launchctl print system/{label} >/dev/null 2>&1 && echo yes || echo no', timeout_sec=10)
    if loaded_out.strip().lower() == 'yes':
        return True
    disabled_out, _ = _run_shell_command_timeout(f'launchctl print-disabled system 2>/dev/null | grep -F "\"{label}\"" >/dev/null 2>&1 && echo yes || echo no', timeout_sec=10)
    return disabled_out.strip().lower() == 'yes'


def _mac_is_protected_service(plist_path, label):
    return label.startswith('com.apple.') or str(plist_path).startswith('/System/Library/')


def _mac_remote_desktop_tool_status():
    candidates = [
        Path('/Applications/Remote Desktop.app'),
        Path('/Applications/Apple Remote Desktop.app'),
        Path('/System/Applications/Screen Sharing.app'),
        Path('/System/Library/CoreServices/Applications/Screen Sharing.app'),
    ]
    found = [str(p) for p in candidates if p.exists()]
    if found:
        return 'present', found
    return 'not_present', []


def _mac_port_is_listening(port):
    return str(port) in _mac_get_listening_ports()


def _mac_service_label_exists(label):
    loaded_out, _ = _run_shell_command_timeout(f'launchctl print system/{label} >/dev/null 2>&1 && echo yes || echo no', timeout_sec=10)
    if loaded_out.strip().lower() == 'yes':
        return True
    disabled_out, _ = _run_shell_command_timeout(f'launchctl print-disabled system 2>/dev/null | grep -F "\"{label}\"" >/dev/null 2>&1 && echo yes || echo no', timeout_sec=10)
    return disabled_out.strip().lower() == 'yes'


def _mac_toggle_ssh(enable):
    action = 'enable' if enable else 'disable'
    cmds = []
    if enable:
        cmds.extend([
            'launchctl enable system/com.openssh.sshd',
            'launchctl kickstart -k system/com.openssh.sshd',
        ])
    else:
        cmds.extend([
            'launchctl bootout system/com.openssh.sshd',
            'launchctl disable system/com.openssh.sshd',
        ])

    ok = True
    last_err = ''
    for cmd in cmds:
        _, err = _run_shell_command_timeout(cmd, timeout_sec=20)
        if err:
            ok = False
            last_err = err
            break
    listening = _mac_port_is_listening('22')
    rows = [{
        'service': 'ssh',
        'requested_action': action,
        'systemsetup_state': 'launchctl-managed',
        'port_22_listening': 'yes' if listening else 'no',
        'command_execution': 'success' if ok else 'failed',
        'error': last_err,
    }]
    display_and_export('macos_ir_service_status_ssh', rows)


def _mac_toggle_launchd_service(service_name, labels, enable, verify_ports=None):
    action = 'enable' if enable else 'disable'
    existing_labels = [l for l in labels if _mac_service_label_exists(l)]
    if not existing_labels:
        rows = [{
            'service': service_name,
            'requested_action': action,
            'result': 'Service label not present on this macOS build',
            'note': 'This service may be removed/unsupported in current macOS versions',
        }]
        display_and_export(f'macos_ir_service_status_{service_name}', rows)
        return

    label, enabled_state, active_state = _mac_service_state(existing_labels)
    if active_state == 'absent':
        tool_state, tool_paths = _mac_remote_desktop_tool_status() if service_name == 'remote_desktop' else ('n/a', [])
        rows = [{
            'service': service_name,
            'requested_action': action,
            'label_checked': label or ','.join(existing_labels),
            'launchctl_enabled_state': 'unsupported',
            'launchctl_active_state': 'absent',
            'remote_desktop_tool_state': tool_state,
            'remote_desktop_tool_paths': '; '.join(tool_paths) if tool_paths else '',
            'result': 'legacy service not present on this macOS build',
            'note': 'telnet, ftp and some screen-sharing/RDP labels are not shipped on modern macOS releases. Use Sharing settings for screen sharing/remote management instead.',
        }]
        display_and_export(f'macos_ir_service_status_{service_name}', rows)
        return

    _mac_service_toggle(existing_labels, action, verify_ports=verify_ports)
    ports = verify_ports or []
    port_state = {f'port_{p}_listening': ('yes' if _mac_port_is_listening(p) else 'no') for p in ports}
    row = {
        'service': service_name,
        'requested_action': action,
        'label_checked': label or ','.join(existing_labels),
        'launchctl_enabled_state': enabled_state,
        'launchctl_active_state': active_state,
    }
    if service_name == 'remote_desktop':
        tool_state, tool_paths = _mac_remote_desktop_tool_status()
        row['remote_desktop_tool_state'] = tool_state
        row['remote_desktop_tool_paths'] = '; '.join(tool_paths) if tool_paths else ''
        if tool_state == 'not_present':
            row['note'] = 'Remote Desktop client app was not found. Screen sharing/remote management may still be available through macOS Sharing settings, but Apple Remote Desktop app-based workflows are unavailable.'
    row.update(port_state)
    display_and_export(f'macos_ir_service_status_{service_name}', [row])


def _mac_service_toggle(label_candidates, action, verify_ports=None):
    action = (action or '').lower().strip()
    cmds = []
    for label in label_candidates:
        if action == 'disable':
            cmds.extend([
                f'launchctl bootout system/{label}',
                f'launchctl disable system/{label}',
            ])
        else:
            cmds.extend([
                f'launchctl enable system/{label}',
                f'launchctl kickstart -k system/{label}',
            ])

    op_name = f'{action.capitalize()} macOS service(s): {", ".join(label_candidates)}'
    success = True
    last_err = ''
    for cmd in cmds:
        _, err = _run_shell_command_timeout(cmd, timeout_sec=20)
        if err:
            success = False
            last_err = err
            break
    label, enabled, active = _mac_service_state(label_candidates)
    if label:
        console.print(f'[cyan]{op_name} verification: {label} enabled={enabled}, active={active}[/cyan]')
    else:
        console.print(f'[yellow]{op_name} verification: no launchd state detected.[/yellow]')

    if verify_ports:
        expected = [str(p) for p in verify_ports]
        found = [p for p in expected if p in _mac_get_listening_ports()]
        if action == 'enable':
            if found:
                console.print(f'[green]Port verification after enable: listening on {", ".join(found)}[/green]')
            else:
                console.print(f'[yellow]Port verification after enable: expected port(s) {", ".join(expected)} are not listening. Service may be unavailable or requires additional macOS configuration.[/yellow]')
        else:
            if found:
                console.print(f'[yellow]Port verification after disable: still listening on {", ".join(found)}. Additional dependent service may still be active.[/yellow]')
            else:
                console.print(f'[green]Port verification after disable: expected port(s) {", ".join(expected)} are not listening.[/green]')
    if not success and last_err:
        console.print(f'[red]{op_name} failed: {last_err}[/red]')
    return success


def _mac_pf_anchor_file():
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    return outdir / 'macos_pf_block_anchor.conf'


def _mac_pf_reload_from_file(anchor_file):
    cmds = [
        'pfctl -E',
        f'pfctl -a com.parthasarathi.block -f {shlex.quote(str(anchor_file))}',
    ]
    ok = True
    last_err = ''
    for cmd in cmds:
        _, err = _run_shell_command_timeout(cmd, timeout_sec=20)
        if err:
            ok = False
            last_err = err
            break
    if not ok and last_err:
        console.print(f'[red]Reload macOS PF anchor rules failed: {last_err}[/red]')
    return ok


def _mac_pf_block_ip(ip, direction):
    anchor_file = _mac_pf_anchor_file()
    lines = []
    if anchor_file.exists():
        lines = [ln.strip() for ln in anchor_file.read_text(encoding='utf-8', errors='ignore').splitlines() if ln.strip()]

    if direction == 'inbound':
        rule = f'block drop in quick from {ip} to any'
    else:
        rule = f'block drop out quick to {ip}'

    if rule in lines:
        console.print(f'[yellow]Rule already present for {ip} ({direction}).[/yellow]')
        return

    lines.append(rule)
    anchor_file.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')
    _mac_pf_reload_from_file(anchor_file)
    console.print(f'[green]Blocked {direction} IP via PF anchor: {ip}[/green]')


def _mac_pf_unblock_ip(ip, direction):
    anchor_file = _mac_pf_anchor_file()
    if not anchor_file.exists():
        console.print('[yellow]No PF anchor rules found for ParthaSarathi.[/yellow]')
        return

    lines = [ln.strip() for ln in anchor_file.read_text(encoding='utf-8', errors='ignore').splitlines() if ln.strip()]
    if direction == 'inbound':
        new_lines = [ln for ln in lines if f' from {ip} ' not in f' {ln} ']
    else:
        new_lines = [ln for ln in lines if f' to {ip}' not in ln]

    if len(new_lines) == len(lines):
        console.print(f'[yellow]No matching PF rule found for {ip} ({direction}).[/yellow]')
        return

    anchor_file.write_text('\n'.join(new_lines) + ('\n' if new_lines else ''), encoding='utf-8')
    _mac_pf_reload_from_file(anchor_file)
    console.print(f'[green]Unblocked {direction} IP via PF anchor: {ip}[/green]')


def macos_system_context():
    rows = []
    cmds = {
        'hostname': 'hostname',
        'os_version': 'sw_vers',
        'kernel': 'uname -a',
        'uptime': 'uptime',
        'sip_status': 'csrutil status',
        'timezone': 'systemsetup -gettimezone',
    }
    for key, cmd in cmds.items():
        res = run_command(cmd, shell=True)
        val = res[0].get('_output', '').strip() if res and isinstance(res, list) else ''
        if val:
            rows.append({'key': key, 'value': val})
    if not rows:
        rows = [{'status': 'Failed to collect macOS system context'}]
    display_and_export('macos_system_context', rows)


def macos_process_snapshot():
    out, err = _run_first_success(['ps -axo pid,user,%cpu,%mem,lstart,command | head -n 400'])
    if not out:
        display_and_export('macos_process_snapshot', [{'status': 'Failed to collect process snapshot', 'error': err or 'ps command failed'}])
        return

    rows = []
    lines = out.splitlines()
    for ln in lines[1:]:
        s = ln.strip()
        if not s:
            continue
        m = re.match(r'^(\d+)\s+(\S+)\s+([\d\.]+)\s+([\d\.]+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\s+(.*)$', s)
        if not m:
            continue
        rows.append({
            'pid': m.group(1),
            'user': m.group(2),
            'cpu_percent': m.group(3),
            'mem_percent': m.group(4),
            'started': m.group(5),
            'command': m.group(6)[:220],
        })

    if not rows:
        rows = _rows_from_lines('macos_process_snapshot', lines, field='process')
    display_and_export('macos_process_snapshot', rows)


def macos_process_tree_of_pid():
    """Show ancestor chain and descendant tree for a selected PID on macOS."""
    pid_in = console.input('Enter PID for process tree: ').strip()
    if not pid_in.isdigit():
        console.print('[red]Invalid PID[/red]')
        return

    target_pid = int(pid_in)
    out, err = _run_first_success(['ps -axo pid,ppid,command'])
    if not out:
        display_and_export('macos_process_tree_of_pid', [{'status': 'Failed to collect process table', 'error': err or 'ps command failed'}])
        return

    nodes = {}
    for ln in out.splitlines()[1:]:
        s = ln.strip()
        if not s:
            continue
        m = re.match(r'^(\d+)\s+(\d+)\s+(.*)$', s)
        if not m:
            continue
        pid = int(m.group(1))
        ppid = int(m.group(2))
        cmd = m.group(3).strip()
        nodes[pid] = {'ppid': ppid, 'command': cmd}

    if target_pid not in nodes:
        display_and_export('macos_process_tree_of_pid', [{'status': f'PID {target_pid} not found in current process snapshot'}])
        return

    def _risk_from_command(command_text):
        txt = (command_text or '').lower()
        factors = []
        checks = [
            ('curl', 'network_download_tool'),
            ('wget', 'network_download_tool'),
            ('nc ', 'netcat_socket_tool'),
            ('ncat', 'netcat_socket_tool'),
            ('socat', 'socket_tunnel_tool'),
            ('base64', 'base64_obfuscation_hint'),
            ('python -c', 'inline_code_execution'),
            ('python3 -c', 'inline_code_execution'),
            ('osascript', 'apple_script_execution'),
            ('sh -c', 'shell_command_wrapper'),
            ('bash -c', 'shell_command_wrapper'),
            ('zsh -c', 'shell_command_wrapper'),
            ('launchctl bootstrap', 'launchd_persistence_operation'),
        ]
        for needle, label in checks:
            if needle in txt:
                factors.append(label)

        if len(factors) >= 3:
            level = 'high'
        elif len(factors) == 2:
            level = 'medium'
        elif len(factors) == 1:
            level = 'low'
        else:
            level = 'none'
        return level, '; '.join(factors)

    children = {}
    for pid, meta in nodes.items():
        ppid = meta['ppid']
        children.setdefault(ppid, []).append(pid)
    for ppid in children:
        children[ppid] = sorted(children[ppid])

    ancestry = []
    seen = set()
    cur = target_pid
    while cur in nodes and cur not in seen:
        seen.add(cur)
        ancestry.append(cur)
        parent = nodes[cur]['ppid']
        if parent == cur:
            break
        cur = parent

    rows = []
    lineage = list(reversed(ancestry))
    for depth, pid in enumerate(lineage):
        role = 'target' if pid == target_pid else 'ancestor'
        command = nodes[pid]['command'][:240]
        risk_level, risk_flags = _risk_from_command(command)
        indent = '  ' * depth
        rows.append({
            'pid': pid,
            'ppid': nodes[pid]['ppid'],
            'role': role,
            'depth': depth,
            'tree_node': f'{indent}↳ {pid}',
            'command': command,
            'risk_level': risk_level,
            'risk_flags': risk_flags,
        })

    visited = set(lineage)

    def _add_descendants(parent_pid, depth):
        for child_pid in children.get(parent_pid, []):
            if child_pid in visited:
                continue
            visited.add(child_pid)
            command = nodes[child_pid]['command'][:240]
            risk_level, risk_flags = _risk_from_command(command)
            indent = '  ' * depth
            rows.append({
                'pid': child_pid,
                'ppid': nodes[child_pid]['ppid'],
                'role': 'descendant',
                'depth': depth,
                'tree_node': f'{indent}↳ {child_pid}',
                'command': command,
                'risk_level': risk_level,
                'risk_flags': risk_flags,
            })
            _add_descendants(child_pid, depth + 1)

    _add_descendants(target_pid, len(lineage))
    display_and_export('macos_process_tree_of_pid', rows)


def macos_logged_in_users():
    _mac_rows_from_command('macos_logged_in_users', ['who', 'w'], field='session')


def _mac_get_listener_lines():
    """Return listener lines from lsof/netstat without treating empty results as command failures."""
    lines = []
    commands = [
        'lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true',
        'netstat -anv -p tcp 2>/dev/null | grep LISTEN || true',
    ]
    for cmd in commands:
        res = run_command(cmd, shell=True)
        out = res[0].get('_output', '') if res and isinstance(res, list) else ''
        if out and out.strip():
            for ln in out.splitlines():
                s = ln.strip()
                if s:
                    lines.append(s)
            if lines:
                break
    return lines


def macos_listening_ports():
    lines = _mac_get_listener_lines()
    if not lines:
        display_and_export('macos_listening_ports', [{'status': 'No listening ports detected from current snapshot'}])
        return
    rows = _rows_from_lines('macos_listening_ports', lines, field='listener')
    display_and_export('macos_listening_ports', rows)


def macos_network_connections():
    _mac_rows_from_command('macos_network_connections', ['netstat -anv', 'lsof -nP -i'], field='connection')


def macos_firewall_rules_snapshot():
    rows = []
    for cmd, key in [
        ('pfctl -sr', 'pf_rules'),
        ('pfctl -a com.parthasarathi.block -s rules', 'pf_anchor_rules'),
        ('pfctl -a com.parthasarathi.isolate -s rules', 'pf_isolation_anchor_rules'),
        ('pfctl -s all', 'pf_state'),
        ('/usr/libexec/ApplicationFirewall/socketfilterfw --listapps', 'app_firewall_apps'),
        ('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate', 'app_firewall_state'),
    ]:
        res = run_command(cmd, shell=True)
        out = res[0].get('_output', '').strip() if res and isinstance(res, list) else ''
        if out:
            rows.append({'section': key, 'output': out})
    if not rows:
        rows = [{'status': 'No firewall data collected'}]
    display_and_export('macos_firewall_rules_snapshot', rows)


def macos_exposed_services():
    lines = _mac_get_listener_lines()
    if not lines:
        display_and_export('macos_exposed_services', [{'status': 'No exposed/risky listening services detected from socket snapshot'}])
        return
    risk_ports = {
        '21': ('ftp', 'High', 'Plaintext file transfer'),
        '22': ('ssh', 'High', 'Remote administration surface'),
        '23': ('telnet', 'Critical', 'Plaintext remote shell service'),
        '3389': ('rdp', 'High', 'Remote desktop exposure'),
        '5900': ('screensharing', 'High', 'Remote control exposure'),
    }
    rows = []
    for ln in lines:
        line = ln.strip()
        m = re.search(r':(\d+)\b', line)
        if not m:
            continue
        port = m.group(1)
        if port not in risk_ports:
            continue
        app, sev, hint = risk_ports[port]
        rows.append({
            'service_name': app,
            'port': port,
            'severity': sev,
            'evidence': line,
            'risk_hint': hint,
        })
    if not rows:
        rows = [{'status': 'No exposed/risky listening services detected from socket snapshot'}]
    display_and_export('macos_exposed_services', rows)


def macos_services_snapshot():
    _mac_rows_from_command('macos_services_snapshot', ['launchctl list'], field='service')


def macos_startup_persistence():
    _mac_rows_from_command('macos_startup_persistence', [
        'find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents -maxdepth 2 -name "*.plist" 2>/dev/null | head -n 400',
        'osascript -e "tell application \"System Events\" to get the name of every login item" 2>/dev/null',
    ], field='entry')


def macos_auth_events_recent():
    _mac_rows_from_command('macos_auth_events_recent', [
        'log show --style compact --last 2h --predicate "eventMessage CONTAINS[c] \"authentication\" OR process == \"sudo\" OR process == \"sshd\"" | head -n 300',
    ], field='auth_event')


def macos_sudoers_and_privilege_paths():
    _mac_rows_from_command('macos_sudoers_and_privilege_paths', [
        "grep -RniE 'NOPASSWD|ALL\\s*=\\s*\\(ALL(:ALL)?\\)\\s*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 300",
        'cat /etc/sudoers 2>/dev/null | head -n 300',
    ], field='entry')


def macos_user_startup_persistence():
    _mac_rows_from_command('macos_user_startup_persistence', [
        'find ~/Library/LaunchAgents -maxdepth 2 -name "*.plist" 2>/dev/null',
        'ls -la ~/.zshrc ~/.zprofile ~/.bash_profile ~/.bashrc 2>/dev/null',
    ], field='entry')


def macos_recent_privilege_events():
    _mac_rows_from_command('macos_recent_privilege_events', [
        'log show --style compact --last 2h --predicate "process == \"sudo\" OR eventMessage CONTAINS[c] \"privilege\"" | head -n 300',
    ], field='event')


def macos_kernel_extensions():
    rows = []

    kextstat_out, _ = _run_first_success(['kextstat 2>/dev/null | head -n 300'])
    if kextstat_out:
        for ln in kextstat_out.splitlines():
            s = ln.strip()
            if not s or s.lower().startswith('index') or s.lower().startswith('loaded by'):
                continue
            m = re.match(r'^(\d+)\s+(\d+)\s+0x[0-9a-fA-F]+\s+([^\s]+)\s+([^\s]+)\s+<([^>]+)>\s*(.*)$', s)
            if m:
                rows.append({
                    'source': 'kextstat',
                    'index': m.group(1),
                    'refs': m.group(2),
                    'bundle_id': m.group(3),
                    'version': m.group(4),
                    'state': m.group(5),
                    'details': m.group(6),
                })
            else:
                rows.append({'source': 'kextstat', 'bundle_id': '', 'version': '', 'state': '', 'details': s})

    kmutil_out, _ = _run_first_success(['kmutil showloaded 2>/dev/null | head -n 300'])
    if kmutil_out:
        for ln in kmutil_out.splitlines():
            s = ln.strip()
            if not s or s.lower().startswith('no variant specified'):
                continue
            rows.append({'source': 'kmutil', 'bundle_id': '', 'version': '', 'state': '', 'details': s})

    sysext_out, _ = _run_first_success(['systemextensionsctl list 2>/dev/null | head -n 300'])
    if sysext_out:
        for ln in sysext_out.splitlines():
            s = ln.rstrip()
            if not s:
                continue
            rows.append({'source': 'systemextensionsctl', 'bundle_id': '', 'version': '', 'state': '', 'details': s.strip()})

    if not rows:
        rows = [{'status': 'No kernel/system extension data collected'}]
    display_and_export('macos_kernel_extensions', rows)


def macos_launchd_unit_anomalies():
    _mac_rows_from_command('macos_launchd_unit_anomalies', [
        'launchctl list | head -n 400',
        'find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents -name "*.plist" 2>/dev/null | grep -Ei "tmp|users/Shared|/private/var/tmp"',
    ], field='entry')


def macos_network_route_dns():
    rows = []
    for cmd, sec in [
        ('route -n get default', 'default_route'),
        ('ifconfig', 'interfaces'),
        ('scutil --dns', 'dns'),
    ]:
        res = run_command(cmd, shell=True)
        out = res[0].get('_output', '').strip() if res and isinstance(res, list) else ''
        if out:
            rows.append({'section': sec, 'output': out[:12000]})
    if not rows:
        rows = [{'status': 'No network route/DNS data found'}]
    display_and_export('macos_network_route_dns', rows)


def macos_user_accounts_and_group_privileges():
    def _parse_key_value_blocks(text):
        blocks = []
        current = {}
        for line in text.splitlines():
            s = line.strip()
            if not s:
                if current:
                    blocks.append(current)
                    current = {}
                continue
            if ':' in s:
                key, value = s.split(':', 1)
                current[key.strip().lower()] = value.strip()
        if current:
            blocks.append(current)
        return blocks

    rows = []

    user_out, _ = _run_first_success(['dscacheutil -q user', 'dscl . -list /Users UniqueID'])
    if user_out:
        for block in _parse_key_value_blocks(user_out):
            rows.append({
                'category': 'user_account',
                'name': block.get('name', block.get('user name', '')),
                'uid': block.get('uid', block.get('uniqueid', '')),
                'gid': block.get('gid', ''),
                'home': block.get('dir', block.get('home directory', '')),
                'shell': block.get('shell', ''),
                'source': 'dscacheutil/dscl',
            })

    group_out, _ = _run_first_success(['dscacheutil -q group', 'dscl . -list /Groups'])
    if group_out:
        for block in _parse_key_value_blocks(group_out):
            members = block.get('users', block.get('groupmembers', block.get('membername', '')))
            rows.append({
                'category': 'group_privilege',
                'name': block.get('name', block.get('group name', '')),
                'gid': block.get('gid', block.get('group id', '')),
                'members': members,
                'source': 'dscacheutil/dscl',
            })

    admin = run_command('dseditgroup -o checkmember -m $(whoami) admin 2>/dev/null', shell=True)
    if admin and isinstance(admin, list) and admin[0].get('_output', '').strip():
        rows.append({
            'category': 'current_user_privilege',
            'name': 'admin_membership',
            'value': admin[0]['_output'].strip(),
            'source': 'dseditgroup',
        })

    if not rows:
        rows = [{'category': 'summary', 'name': 'no data', 'value': 'No user/group privilege data found'}]

    display_and_export('macos_user_accounts_and_group_privileges', rows)


def macos_installed_apps():
    """List installed macOS apps with version, created/modified timestamps, and binary hash when possible."""
    import hashlib
    import plistlib

    app_roots = [
        Path('/Applications'),
        Path('/System/Applications'),
        Path('/System/Library/CoreServices/Applications'),
        Path.home() / 'Applications',
    ]

    app_paths = set()
    for root in app_roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            for app in root.rglob('*.app'):
                if app.is_dir():
                    app_paths.add(app)
        except Exception:
            continue

    rows = []
    for app_path in sorted(app_paths):
        name = app_path.stem
        version = ''
        created_at = ''
        modified_at = ''
        main_exec_path = ''
        sha256_val = 'N/A'

        try:
            st = app_path.stat()
            created_ts = getattr(st, 'st_birthtime', st.st_ctime)
            created_at = datetime.fromtimestamp(created_ts).isoformat(sep=' ', timespec='seconds')
            modified_at = datetime.fromtimestamp(st.st_mtime).isoformat(sep=' ', timespec='seconds')
        except Exception:
            pass

        info_plist = app_path / 'Contents' / 'Info.plist'
        if info_plist.exists():
            try:
                with open(info_plist, 'rb') as f:
                    p = plistlib.load(f)
                bundle_name = p.get('CFBundleDisplayName') or p.get('CFBundleName')
                if bundle_name:
                    name = str(bundle_name)
                version = str(p.get('CFBundleShortVersionString') or p.get('CFBundleVersion') or '')
                executable = p.get('CFBundleExecutable')
                if executable:
                    candidate = app_path / 'Contents' / 'MacOS' / str(executable)
                    if candidate.exists() and candidate.is_file():
                        main_exec_path = str(candidate)
            except Exception:
                pass

        if main_exec_path:
            try:
                h = hashlib.sha256()
                with open(main_exec_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(chunk)
                sha256_val = h.hexdigest()
            except Exception:
                sha256_val = 'N/A'

        rows.append({
            'name': name,
            'version': version or 'unknown',
            'install_location': str(app_path),
            'created_at': created_at,
            'modified_at': modified_at,
            'main_executable': main_exec_path,
            'sha256': sha256_val,
        })

    if not rows:
        rows = [{'status': 'No installed macOS applications found in standard app locations'}]
    display_and_export('macos_installed_apps', rows)


def macos_quarantine_attributes():
    _mac_rows_from_command('macos_quarantine_attributes', [
        'find ~/Downloads /Applications -maxdepth 3 -type f -print0 2>/dev/null | xargs -0 xattr -p com.apple.quarantine 2>/dev/null | head -n 300',
    ], field='quarantine')


def macos_recently_deleted_files():
    rows = []
    privacy_denied = False
    candidate_dirs = []
    home_dir = Path.home()
    candidate_dirs.append(home_dir / '.Trash')

    env_home = os.getenv('HOME', '').strip()
    if env_home:
        candidate_dirs.append(Path(env_home) / '.Trash')

    users_root = Path('/Users')
    if users_root.exists():
        try:
            for user_dir in users_root.iterdir():
                if user_dir.is_dir():
                    candidate_dirs.append(user_dir / '.Trash')
        except Exception:
            pass

    volumes_root = Path('/Volumes')
    if volumes_root.exists():
        try:
            for vol in volumes_root.iterdir():
                trashes_root = vol / '.Trashes'
                if trashes_root.exists() and trashes_root.is_dir():
                    candidate_dirs.append(trashes_root)
                    for uid_dir in trashes_root.iterdir():
                        if uid_dir.is_dir():
                            candidate_dirs.append(uid_dir)
        except Exception:
            pass

    seen = set()
    unique_dirs = []
    for d in candidate_dirs:
        key = str(d)
        if key in seen:
            continue
        seen.add(key)
        unique_dirs.append(d)

    collected = []
    for base in unique_dirs:
        if not base.exists() or not base.is_dir():
            continue
        try:
            for item in base.iterdir():
                if len(collected) >= 400:
                    break
                try:
                    st = item.stat()
                    collected.append((item, st.st_mtime, str(base)))
                except Exception:
                    continue
                if item.is_dir():
                    try:
                        for nested in item.iterdir():
                            if len(collected) >= 400:
                                break
                            try:
                                st_nested = nested.stat()
                                collected.append((nested, st_nested.st_mtime, str(base)))
                            except Exception:
                                continue
                    except Exception:
                        pass
        except Exception:
            privacy_denied = True
            continue
        if len(collected) >= 400:
            break

    for path_obj, mtime_ts, source_base in sorted(collected, key=lambda x: x[1], reverse=True):
        source = 'user_trash' if '/.Trash' in source_base else 'volume_trash'
        rows.append({
            'source': source,
            'path': str(path_obj),
            'mtime': datetime.fromtimestamp(mtime_ts).strftime('%Y-%m-%d %H:%M:%S'),
        })

    if not rows:
        # Finder-based fallback (best effort).
        finder = run_command('osascript -e "tell application \"Finder\" to get POSIX path of (every item of trash as alias)" 2>/dev/null', shell=True)
        if finder and isinstance(finder, list) and '_error' in finder[0]:
            ferr = finder[0].get('_error', '').lower()
            if 'not authorized' in ferr or 'not permitted' in ferr or 'denied' in ferr:
                privacy_denied = True
        finder_out = finder[0].get('_output', '').strip() if finder and isinstance(finder, list) else ''
        if finder_out:
            items = []
            for ln in finder_out.splitlines():
                parts = [p.strip() for p in ln.split(',') if p.strip()]
                items.extend(parts if parts else [ln.strip()])
            for p in items[:400]:
                pth = Path(p)
                try:
                    st = pth.stat()
                    rows.append({
                        'source': 'finder_trash',
                        'path': str(pth),
                        'mtime': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    })
                except Exception:
                    rows.append({'source': 'finder_trash', 'path': str(pth), 'mtime': ''})

    if not rows:
        # Additional Finder fallback that only asks for names.
        finder_names = run_command('osascript -e "tell application \"Finder\" to get name of every item of trash" 2>/dev/null', shell=True)
        if finder_names and isinstance(finder_names, list) and '_error' in finder_names[0]:
            ferr = finder_names[0].get('_error', '').lower()
            if 'not authorized' in ferr or 'not permitted' in ferr or 'denied' in ferr:
                privacy_denied = True
        names_out = finder_names[0].get('_output', '').strip() if finder_names and isinstance(finder_names, list) else ''
        if names_out:
            names = []
            for ln in names_out.splitlines():
                parts = [p.strip() for p in ln.split(',') if p.strip()]
                names.extend(parts if parts else [ln.strip()])
            for nm in names[:400]:
                rows.append({'source': 'finder_trash_name', 'path': nm, 'mtime': ''})

    if not rows:
        # Shell fallback in case Python path traversal misses due ACLs/symlinks.
        out, shell_err = _run_first_success([
            'find "$HOME/.Trash" -mindepth 1 -maxdepth 3 -print 2>/dev/null | head -n 400',
            'for p in /Users/*/.Trash /Volumes/*/.Trashes/*; do [ -d "$p" ] && find "$p" -mindepth 1 -maxdepth 3 -print 2>/dev/null; done | head -n 400',
        ])
        if shell_err:
            serr = shell_err.lower()
            if 'operation not permitted' in serr or 'permission denied' in serr or 'not permitted' in serr or 'denied' in serr:
                privacy_denied = True
        if out:
            for ln in out.splitlines():
                path = ln.strip()
                if not path:
                    continue
                mres = run_command(f'stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" {shlex.quote(path)} 2>/dev/null', shell=True)
                mtime = mres[0].get('_output', '').strip() if mres and isinstance(mres, list) else ''
                rows.append({'source': 'shell_trash', 'path': path, 'mtime': mtime})

    if not rows:
        # Minimal manual fallback: top-level listing of current user's Trash.
        ls_res = run_command('ls -1A "$HOME/.Trash" 2>/dev/null | head -n 400', shell=True)
        ls_out = ls_res[0].get('_output', '').strip() if ls_res and isinstance(ls_res, list) else ''
        if ls_out:
            for name in ls_out.splitlines():
                s = name.strip()
                if s:
                    rows.append({'source': 'home_trash_ls', 'path': s, 'mtime': ''})

    if not rows:
        note = 'No recently deleted files were readable from standard Trash locations'
        if privacy_denied:
            note = 'Access appears blocked by macOS privacy controls. Grant Full Disk Access to Terminal/iTerm/VS Code and Python, restart them, then retry.'
        rows = [{'status': 'No recently deleted files found in user/volume Trash locations', 'note': note}]
    display_and_export('macos_recently_deleted_files', rows)


def macos_shell_history_collection():
    _mac_rows_from_command('macos_shell_history_collection', [
        "for h in ~/.zsh_history ~/.bash_history; do [ -f \"$h\" ] && sed 's/^/[history] /' \"$h\"; done | tail -n 300",
    ], field='history')


def macos_tcc_privacy_permissions():
    _mac_rows_from_command('macos_tcc_privacy_permissions', [
        'for db in "/Library/Application Support/com.apple.TCC/TCC.db" "$HOME/Library/Application Support/com.apple.TCC/TCC.db"; do [ -f "$db" ] && echo "===== $db =====" && sqlite3 "$db" "SELECT service, client, auth_value, auth_reason, last_modified FROM access ORDER BY last_modified DESC LIMIT 200;"; done 2>/dev/null',
    ], field='tcc_entry', fallback_status='No readable TCC database entries collected (may require Full Disk Access/root)')


def macos_gatekeeper_assessment():
    rows = []
    checks = {
        'gatekeeper_status': 'spctl --status',
        'gk_auto_rearm': 'defaults read /Library/Preferences/com.apple.security GKAutoRearm 2>/dev/null || true',
        'xprotect_version': 'defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>/dev/null || true',
    }
    for key, cmd in checks.items():
        res = run_command(cmd, shell=True)
        out = res[0].get('_output', '').strip() if res and isinstance(res, list) else ''
        err = res[0].get('_error', '').strip() if res and isinstance(res, list) else ''
        rows.append({'check': key, 'output': out or err or 'n/a'})

    assess = run_command('find /Applications -maxdepth 2 -name "*.app" 2>/dev/null | head -n 25 | while read -r app; do spctl --assess -vv "$app" 2>&1 | sed "s|^|$app :: |"; done', shell=True)
    if assess and isinstance(assess, list) and assess[0].get('_output', '').strip():
        for ln in assess[0]['_output'].splitlines()[:300]:
            s = ln.strip()
            if s:
                rows.append({'check': 'spctl_assess', 'output': s})

    if not rows:
        rows = [{'status': 'No Gatekeeper/notarization indicators collected'}]
    display_and_export('macos_gatekeeper_assessment', rows)


def macos_usb_external_device_timeline():
    rows = []

    log_out, _ = _run_first_success([
        'log show --style compact --last 7d --predicate "eventMessage CONTAINS[c] \"USB\" OR eventMessage CONTAINS[c] \"IOUSB\" OR process == \"diskarbitrationd\" OR eventMessage CONTAINS[c] \"mounted\" OR eventMessage CONTAINS[c] \"unmounted\"" 2>/dev/null | head -n 500',
    ])
    if log_out:
        for ln in log_out.splitlines()[:500]:
            s = ln.strip()
            if not s:
                continue
            action = 'event'
            low = s.lower()
            if 'unmount' in low or 'detach' in low or 'disconnected' in low:
                action = 'disconnect_or_unmount'
            elif 'mount' in low or 'attach' in low or 'connected' in low:
                action = 'connect_or_mount'

            timestamp = ''
            m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)\s+(.*)$', s)
            details = s
            if m:
                timestamp = m.group(1)
                details = m.group(2)

            rows.append({
                'source': 'unified_log',
                'timestamp': timestamp,
                'action': action,
                'details': details[:1500],
            })

    sp_out, _ = _run_first_success(['system_profiler SPUSBDataType -detailLevel mini 2>/dev/null | head -n 600'])
    if sp_out:
        for ln in sp_out.splitlines()[:600]:
            s = ln.strip()
            if not s:
                continue
            if s.endswith(':') or 'product id' in s.lower() or 'vendor id' in s.lower() or 'serial number' in s.lower() or 'bsd name' in s.lower() or 'removable media' in s.lower():
                rows.append({
                    'source': 'system_profiler_usb_snapshot',
                    'timestamp': '',
                    'action': 'snapshot',
                    'details': s[:1500],
                })

    ioreg_out, _ = _run_first_success(['ioreg -p IOUSB -l 2>/dev/null | head -n 400'])
    if ioreg_out:
        for ln in ioreg_out.splitlines()[:400]:
            s = ln.strip()
            if not s:
                continue
            if 'usb' in s.lower() or 'vendor' in s.lower() or 'product' in s.lower() or 'serial' in s.lower():
                rows.append({
                    'source': 'ioreg_usb_snapshot',
                    'timestamp': '',
                    'action': 'snapshot',
                    'details': s[:1500],
                })

    disk_out, _ = _run_first_success(['diskutil list external 2>/dev/null'])
    if disk_out:
        for ln in disk_out.splitlines()[:250]:
            s = ln.strip()
            if s:
                rows.append({
                    'source': 'diskutil_external_snapshot',
                    'timestamp': '',
                    'action': 'snapshot',
                    'details': s[:1500],
                })

    if not rows:
        rows = [{'status': 'No USB/external timeline rows collected (logs may require additional privileges or there were no recent events)'}]

    display_and_export('macos_usb_external_device_timeline', rows)


def macos_login_session_correlation():
    rows = []
    who_out, _ = _run_first_success(['who'])
    if who_out:
        for ln in who_out.splitlines()[:200]:
            s = ln.strip()
            if s:
                rows.append({'source': 'who', 'entry': s})

    last_out, _ = _run_first_success(['last | head -n 150'])
    if last_out:
        for ln in last_out.splitlines()[:150]:
            s = ln.strip()
            if s:
                rows.append({'source': 'last', 'entry': s})

    log_out, _ = _run_first_success([
        'log show --style syslog --last 24h --predicate "process == \"loginwindow\" OR process == \"sshd\" OR eventMessage CONTAINS[c] \"session\"" 2>/dev/null | head -n 200',
    ])
    if log_out:
        for ln in log_out.splitlines()[:200]:
            s = ln.strip()
            if s:
                rows.append({'source': 'unified_log', 'entry': s})

    if not rows:
        rows = [{'status': 'No login/session correlation rows collected'}]
    display_and_export('macos_login_session_correlation', rows)


def macos_recent_executable_writes_execution_correlation():
    rows = []
    writes_out, _ = _run_first_success([
        'find ~/Downloads /tmp /private/tmp -type f -mtime -7 -perm -111 2>/dev/null | head -n 200',
    ])
    if writes_out:
        for ln in writes_out.splitlines()[:200]:
            s = ln.strip()
            if s:
                rows.append({'source': 'recent_executable_write', 'entry': s})

    exec_out, _ = _run_first_success([
        'log show --style syslog --last 24h --predicate "eventMessage CONTAINS[c] \"exec\" OR process == \"launchservicesd\"" 2>/dev/null | head -n 200',
    ])
    if exec_out:
        for ln in exec_out.splitlines()[:200]:
            s = ln.strip()
            if s:
                rows.append({'source': 'execution_log', 'entry': s})

    if not rows:
        rows = [{'status': 'No executable-write/execution correlation rows collected'}]
    display_and_export('macos_recent_executable_writes_execution_correlation', rows)


def macos_world_writable_and_suid_scan():
    _mac_rows_from_command('macos_world_writable_and_suid_scan', [
        'find / -xdev \( -type f -perm -4000 -o -type d -perm -0002 \) 2>/dev/null | head -n 400',
    ], field='path', fallback_status='No world-writable/SUID rows collected')


def macos_safari_history_summary():
    _mac_rows_from_command('macos_safari_history_summary', [
        "DB=\"$HOME/Library/Safari/History.db\"; [ -f \"$DB\" ] && sqlite3 \"$DB\" \"SELECT datetime(visit_time+978307200, 'unixepoch', 'localtime') as ts, url, title FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id ORDER BY visit_time DESC LIMIT 200;\"",
    ], field='history', fallback_status='No Safari History.db data collected')


def macos_file_metadata():
    file_details()


def incident_response_menu_macos():
    """macOS-focused incident response actions with session-level dry-run."""
    ir_dry_run = console.input('Enable dry-run for all high-impact actions this IR session? (y/N): ').strip().lower() == 'y'
    if ir_dry_run:
        console.print('[cyan]Dry-run is ON for this macOS IR session.[/cyan]')

    while True:
        console.print('\n[bold yellow]macOS Incident Response Actions:[/bold yellow]')
        console.print('1.  List processes')
        console.print('2.  Kill process by PID')
        console.print('3.  Run command')
        console.print('4.  List existing firewall rules')
        console.print('5.  Block IP')
        console.print('6.  Unblock IP')
        console.print('7.  Stop service')
        console.print('8.  Remove/delete service')
        console.print('9.  Network connections snapshot')
        console.print('10. Disable SSH service')
        console.print('11. Enable SSH service')
        console.print('12. Disable Telnet service')
        console.print('13. Enable Telnet service')
        console.print('14. Disable FTP service')
        console.print('15. Enable FTP service')
        console.print('16. Disable RDP service')
        console.print('17. Enable RDP service')
        console.print('18. Isolate host (safe mode)')
        console.print('19. Rollback host isolation')
        console.print('20. User management')
        console.print('21. Remove suspicious cron entry')
        console.print('22. Kill process by port')
        console.print('23. Quarantine file')
        console.print('24. Restore quarantined file')
        console.print('25. Back to main menu')
        choice = console.input('Choose action (1-25): ').strip()

        if choice == '1':
            macos_process_snapshot()
        elif choice == '2':
            pid = console.input('PID to kill: ').strip()
            if not pid.isdigit():
                console.print('[red]Invalid PID[/red]')
                continue
            if ir_dry_run:
                _print_ir_dry_run('Kill macOS process by PID', details={'PID': pid}, commands=[f'kill -9 {pid}'])
                continue
            res = run_command(f'kill -9 {pid}', shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Failed to kill process: {res[0]['_error']}[/red]")
            else:
                console.print(f'[green]Process terminated: {pid}[/green]')
        elif choice == '3':
            cmd = console.input('Command to run: ').strip()
            if not cmd:
                continue
            if ir_dry_run:
                _print_ir_dry_run('Run macOS command', details={'Command': cmd}, commands=[cmd])
                continue
            res = run_command(cmd, shell=True)
            if res and isinstance(res, list) and '_error' in res[0]:
                console.print(f"[red]Command failed: {res[0]['_error']}[/red]")
            else:
                console.print(res[0].get('_output', '') if res and isinstance(res, list) else '')
        elif choice == '4':
            macos_firewall_rules_snapshot()
        elif choice == '5':
            ip = console.input('IP address to block: ').strip()
            if not ip:
                continue
            d = console.input('Direction to block (1=inbound, 2=outbound): ').strip()
            if ir_dry_run:
                _print_ir_dry_run('Block IP on macOS', details={'IP': ip, 'Direction': 'inbound' if d == '1' else 'outbound'}, commands=['pfctl anchor update'])
                continue
            _mac_pf_block_ip(ip, 'inbound' if d == '1' else 'outbound')
        elif choice == '6':
            ip = console.input('IP address to unblock: ').strip()
            if not ip:
                continue
            d = console.input('Direction to unblock (1=inbound, 2=outbound): ').strip()
            if ir_dry_run:
                _print_ir_dry_run('Unblock IP on macOS', details={'IP': ip, 'Direction': 'inbound' if d == '1' else 'outbound'}, commands=['pfctl anchor update'])
                continue
            _mac_pf_unblock_ip(ip, 'inbound' if d == '1' else 'outbound')
        elif choice == '7':
            svc = console.input('launchd label to stop (e.g., com.openssh.sshd): ').strip()
            if not svc:
                continue
            if ir_dry_run:
                _print_ir_dry_run('Stop macOS service', details={'Service': svc}, commands=[f'launchctl bootout system/{svc}'])
                continue
            _mac_service_toggle([svc], 'disable')
            label, enabled_state, active_state = _mac_service_state([svc])
            display_and_export('macos_ir_service_stop_verify', [{
                'service_label': svc,
                'resolved_label': label or svc,
                'enabled_state': enabled_state,
                'active_state': active_state,
            }])
        elif choice == '8':
            _mac_remove_service_definition(ir_dry_run=ir_dry_run)
        elif choice == '9':
            macos_network_connections()
        elif choice == '10':
            if not ir_dry_run:
                _mac_toggle_ssh(enable=False)
            else:
                _print_ir_dry_run('Disable SSH on macOS', commands=['systemsetup -setremotelogin off', 'launchctl disable system/com.openssh.sshd'])
        elif choice == '11':
            if not ir_dry_run:
                _mac_toggle_ssh(enable=True)
            else:
                _print_ir_dry_run('Enable SSH on macOS', commands=['systemsetup -setremotelogin on', 'launchctl enable system/com.openssh.sshd'])
        elif choice == '12':
            _mac_toggle_launchd_service('telnet', ['com.apple.telnetd', 'telnetd', 'telnet'], enable=False, verify_ports=['23']) if not ir_dry_run else _print_ir_dry_run('Disable Telnet on macOS', commands=['launchctl disable system/com.apple.telnetd'])
        elif choice == '13':
            _mac_toggle_launchd_service('telnet', ['com.apple.telnetd', 'telnetd', 'telnet'], enable=True, verify_ports=['23']) if not ir_dry_run else _print_ir_dry_run('Enable Telnet on macOS', commands=['launchctl enable system/com.apple.telnetd'])
        elif choice == '14':
            _mac_toggle_launchd_service('ftp', ['com.apple.ftpd', 'ftpd', 'ftp'], enable=False, verify_ports=['21']) if not ir_dry_run else _print_ir_dry_run('Disable FTP on macOS', commands=['launchctl disable system/com.apple.ftpd'])
        elif choice == '15':
            _mac_toggle_launchd_service('ftp', ['com.apple.ftpd', 'ftpd', 'ftp'], enable=True, verify_ports=['21']) if not ir_dry_run else _print_ir_dry_run('Enable FTP on macOS', commands=['launchctl enable system/com.apple.ftpd'])
        elif choice == '16':
            _mac_toggle_launchd_service('remote_desktop', ['com.apple.screensharing', 'org.xrdp.xrdp', 'screensharing'], enable=False, verify_ports=['5900', '3389']) if not ir_dry_run else _print_ir_dry_run('Disable RDP/screen sharing on macOS', commands=['launchctl disable system/com.apple.screensharing'])
        elif choice == '17':
            _mac_toggle_launchd_service('remote_desktop', ['com.apple.screensharing', 'org.xrdp.xrdp', 'screensharing'], enable=True, verify_ports=['5900', '3389']) if not ir_dry_run else _print_ir_dry_run('Enable RDP/screen sharing on macOS', commands=['launchctl enable system/com.apple.screensharing'])
        elif choice == '18':
            _mac_isolate_host_safe_mode(ir_dry_run=ir_dry_run)
        elif choice == '19':
            _mac_run_last_isolation_rollback(ir_dry_run=ir_dry_run)
        elif choice == '20':
            _mac_user_management_menu(ir_dry_run=ir_dry_run)
        elif choice == '21':
            _linux_remove_cron_entry(ir_dry_run=ir_dry_run)
        elif choice == '22':
            _mac_kill_by_port(ir_dry_run=ir_dry_run)
        elif choice == '23':
            _mac_quarantine_file(ir_dry_run=ir_dry_run)
        elif choice == '24':
            _mac_restore_quarantined_file(ir_dry_run=ir_dry_run)
        elif choice == '25':
            break
        else:
            console.print('[yellow]Invalid choice[/yellow]')


def _mac_remove_service_definition(ir_dry_run=False):
    plist_path = console.input('Launchd plist path to remove (e.g., /Library/LaunchDaemons/com.example.demo.plist): ').strip()
    if not plist_path:
        console.print('[red]No plist path entered[/red]')
        return
    plist = Path(plist_path)
    label_guess = plist.stem
    if _mac_is_protected_service(plist, label_guess):
        display_and_export('macos_ir_remove_service_verify', [{
            'plist': str(plist),
            'service': label_guess,
            'result': 'protected system service',
            'note': 'Apple/system launchd services are not removed by this tool; only third-party LaunchDaemons/Agents can be deleted.',
        }])
        console.print('[yellow]Protected Apple/system service detected. No removal claim will be made for it.[/yellow]')
        return
    cmds = [
        f'launchctl bootout system/{label_guess}',
        f'launchctl disable system/{label_guess}',
        f'rm -f {shlex.quote(str(plist))}',
    ]
    if ir_dry_run:
        _print_ir_dry_run('Remove/delete macOS service definition', details={'plist': str(plist), 'label_guess': label_guess}, commands=cmds)
        return
    success = True
    last_err = ''
    for cmd in cmds:
        _, err = _run_shell_command_timeout(cmd, timeout_sec=20)
        if err:
            success = False
            last_err = err
            break
    plist_exists = plist.exists()
    state_out, _ = _run_shell_command_timeout(f'launchctl print system/{label_guess} >/dev/null 2>&1 && echo present || echo absent', timeout_sec=10)
    display_and_export('macos_ir_remove_service_verify', [{
        'plist': str(plist),
        'plist_exists_after_action': 'yes' if plist_exists else 'no',
        'launchctl_label_state': state_out.strip() or 'unknown',
        'command_execution': 'success' if success else 'failed',
        'error': last_err,
    }])
    run_command('launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.logd.plist >/dev/null 2>&1 || true', shell=True)
    console.print(f'[green]Removal attempted for plist: {plist}[/green]')


def _mac_isolation_marker_path():
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    return outdir / 'macos_ir_last_rollback_path.txt'


def _mac_isolate_host_safe_mode(ir_dry_run=False):
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    rollback_file = outdir / f'macos_ir_pf_rollback_{ts}.sh'
    isolate_anchor = outdir / f'macos_ir_pf_isolate_{ts}.conf'
    isolate_anchor.write_text('block drop all\npass quick on lo0 all\n', encoding='utf-8')

    cmds = [
        'pfctl -E',
        f'pfctl -a com.parthasarathi.isolate -f {shlex.quote(str(isolate_anchor))}',
        'route -n add -net 0.0.0.0/1 127.0.0.1',
        'route -n add -net 128.0.0.0/1 127.0.0.1',
    ]
    rollback_cmds = [
        'pfctl -a com.parthasarathi.isolate -f /dev/null',
        'route -n delete -net 0.0.0.0/1 127.0.0.1',
        'route -n delete -net 128.0.0.0/1 127.0.0.1',
    ]

    if ir_dry_run:
        _print_ir_dry_run('macOS safe-mode host isolation (PF)', details={'rollback_file': str(rollback_file), 'anchor': str(isolate_anchor)}, commands=cmds)
        return

    applied = True
    last_err = ''
    for cmd in cmds:
        _, err = _run_shell_command_timeout(cmd, timeout_sec=20)
        if err:
            applied = False
            last_err = err
            break
    if not applied:
        console.print(f'[red]Isolation did not apply. Ensure the command is run with sudo/root privileges. {last_err}[/red]')
        return

    verify = run_command('pfctl -a com.parthasarathi.isolate -s rules', shell=True)
    verify_out = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
    if not verify_out:
        console.print('[yellow]Isolation command executed, but no isolate anchor rules were readable. Verify PF privileges/state manually.[/yellow]')
    route_verify = run_command('route -n get 8.8.8.8 2>/dev/null | grep gateway', shell=True)
    route_out = route_verify[0].get('_output', '').strip() if route_verify and isinstance(route_verify, list) else ''
    display_and_export('macos_ir_isolation_verify', [{
        'pf_anchor_rules': 'present' if verify_out else 'not_readable',
        'route_gateway_check': route_out or 'unavailable',
        'note': 'If internet still works, confirm the route commands succeeded and rerun with sudo/root.',
    }])
    rollback_file.write_text('#!/bin/sh\n' + '\n'.join(rollback_cmds) + '\n', encoding='utf-8')
    run_command(f'chmod +x {shlex.quote(str(rollback_file))}', shell=True)
    _mac_isolation_marker_path().write_text(str(rollback_file), encoding='utf-8')
    console.print('[green]macOS isolation anchor applied (PF).[/green]')
    console.print(f'[cyan]Rollback script saved:[/cyan] {rollback_file}')


def _mac_run_last_isolation_rollback(ir_dry_run=False):
    marker = _mac_isolation_marker_path()
    if not marker.exists():
        console.print('[yellow]No rollback marker found. Run isolation first.[/yellow]')
        return
    rollback_path = marker.read_text(encoding='utf-8').strip()
    if not rollback_path:
        console.print('[yellow]Rollback marker is empty.[/yellow]')
        return
    cmd = f'sh {shlex.quote(rollback_path)}'
    if ir_dry_run:
        _print_ir_dry_run('Rollback macOS safe-mode isolation', commands=[cmd])
        return
    _, err = _run_shell_command_timeout(cmd, timeout_sec=20)
    if err:
        console.print(f'[red]Rollback failed: {err}[/red]')
    else:
        verify = run_command('pfctl -a com.parthasarathi.isolate -s rules', shell=True)
        verify_out = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
        if verify_out:
            console.print('[yellow]Rollback executed, but isolation anchor still has rules. Try sudo and rerun rollback.[/yellow]')
        else:
            console.print(f'[green]Rollback command executed from {rollback_path}; isolation anchor rules cleared.[/green]')


def _mac_list_user_accounts():
    users_out, err_users = _run_first_success(['dscl . -list /Users UniqueID'])
    if not users_out:
        display_and_export('macos_ir_user_accounts', [{'status': 'Failed', 'error': err_users or 'Unable to enumerate users'}])
        return

    user_rows = []
    for ln in users_out.splitlines():
        s = ln.strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            user_rows.append({'username': ' '.join(parts[:-1]), 'uid': parts[-1]})
        else:
            user_rows.append({'username': s, 'uid': ''})
    display_and_export('macos_ir_user_accounts', user_rows)

    group_out, _ = _run_first_success(['dscl . -list /Groups PrimaryGroupID'])
    group_rows = []
    if group_out:
        for ln in group_out.splitlines():
            s = ln.strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) >= 2 and parts[-1].isdigit():
                group_rows.append({'group': ' '.join(parts[:-1]), 'gid': parts[-1]})
            else:
                group_rows.append({'group': s, 'gid': ''})
    if group_rows:
        display_and_export('macos_ir_group_privileges', group_rows)


def _mac_user_management_menu(ir_dry_run=False):
    while True:
        console.print('\n[bold cyan]User management[/bold cyan]')
        console.print('1. List available users details')
        console.print('2. Disable/lock user account')
        console.print('3. Enable/unlock user account')
        console.print('4. Add user account')
        console.print('5. Remove user account')
        console.print('6. Remove user from group')
        console.print('7. Back')
        sub = console.input('Choose (1-7): ').strip()
        if sub == '1':
            _mac_list_user_accounts()
        elif sub == '2':
            user = console.input('Username to disable/lock: ').strip()
            if not user:
                continue
            cmds = [f'pwpolicy -u {shlex.quote(user)} -setpolicy "isDisabled=1"', f'dscl . -create /Users/{shlex.quote(user)} UserShell /usr/bin/false']
            if ir_dry_run:
                _print_ir_dry_run('Disable/lock macOS user account', details={'user': user}, commands=cmds)
            else:
                _linux_execute_command_series('Disable/lock macOS user account', cmds, ir_dry_run=False)
                verify = run_command(f'pwpolicy -u {shlex.quote(user)} -getpolicy 2>/dev/null', shell=True)
                vout = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
                display_and_export('macos_ir_user_disable_verify', [{
                    'user': user,
                    'policy': vout or 'Policy output unavailable',
                }])
        elif sub == '3':
            user = console.input('Username to enable/unlock: ').strip()
            if not user:
                continue
            shell = console.input('Login shell to restore (default /bin/zsh): ').strip() or '/bin/zsh'
            cmds = [f'pwpolicy -u {shlex.quote(user)} -setpolicy "isDisabled=0"', f'dscl . -create /Users/{shlex.quote(user)} UserShell {shlex.quote(shell)}']
            if ir_dry_run:
                _print_ir_dry_run('Enable/unlock macOS user account', details={'user': user, 'shell': shell}, commands=cmds)
            else:
                _linux_execute_command_series('Enable/unlock macOS user account', cmds, ir_dry_run=False)
                verify = run_command(f'dscl . -read /Users/{shlex.quote(user)} UserShell 2>/dev/null', shell=True)
                vout = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
                display_and_export('macos_ir_user_enable_verify', [{
                    'user': user,
                    'shell': vout or shell,
                }])
        elif sub == '4':
            user = console.input('Username to add: ').strip()
            if not user:
                continue
            password = console.input('Password: ').strip()
            cmds = [f'sysadminctl -addUser {shlex.quote(user)} -password {shlex.quote(password)}']
            if ir_dry_run:
                _print_ir_dry_run('Add macOS user account', details={'user': user}, commands=cmds)
            else:
                _linux_execute_command_series('Add macOS user account', cmds, ir_dry_run=False)
                verify = run_command(f'dscl . -read /Users/{shlex.quote(user)} UniqueID 2>/dev/null', shell=True)
                vout = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
                display_and_export('macos_ir_user_add_verify', [{'user': user, 'created': 'yes' if vout else 'unknown', 'details': vout}])
        elif sub == '5':
            user = console.input('Username to remove: ').strip()
            if not user:
                continue
            cmds = [
                f'dseditgroup -o edit -d {shlex.quote(user)} -t user admin',
                f'sysadminctl -deleteUser {shlex.quote(user)}',
                f'dscl . -delete /Users/{shlex.quote(user)}',
            ]
            if ir_dry_run:
                _print_ir_dry_run('Remove macOS user account', details={'user': user}, commands=cmds)
            else:
                _linux_execute_command_series('Remove macOS user account', cmds, ir_dry_run=False)
                verify = run_command(f'dscl . -read /Users/{shlex.quote(user)} >/dev/null 2>&1 && echo present || echo removed', shell=True)
                vout = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
                display_and_export('macos_ir_user_remove_verify', [{'user': user, 'state': vout or 'unknown'}])
        elif sub == '6':
            user = console.input('Username: ').strip()
            group_name = console.input('Group to remove user from: ').strip()
            if not user or not group_name:
                continue
            cmds = [f'dseditgroup -o edit -d {shlex.quote(user)} -t user {shlex.quote(group_name)}']
            if ir_dry_run:
                _print_ir_dry_run('Remove macOS user from group', details={'user': user, 'group': group_name}, commands=cmds)
            else:
                _linux_execute_command_series('Remove macOS user from group', cmds, ir_dry_run=False)
                verify = run_command(f'dseditgroup -o checkmember -m {shlex.quote(user)} {shlex.quote(group_name)} 2>/dev/null', shell=True)
                vout = verify[0].get('_output', '').strip() if verify and isinstance(verify, list) else ''
                display_and_export('macos_ir_group_remove_verify', [{'user': user, 'group': group_name, 'check': vout or 'verification unavailable'}])
        elif sub == '7':
            break
        else:
            console.print('[yellow]Invalid choice[/yellow]')


def _mac_kill_by_port(ir_dry_run=False):
    port = console.input('Port to kill process by: ').strip()
    if not port.isdigit():
        console.print('[red]Invalid port[/red]')
        return
    find_cmd = f'lsof -nP -iTCP:{port} -sTCP:LISTEN -t'
    pids = run_command(find_cmd, shell=True)
    out = pids[0].get('_output', '').strip() if pids and isinstance(pids, list) else ''
    if not out:
        console.print(f'[yellow]No listening process found on port {port}[/yellow]')
        return
    pid_list = [x.strip() for x in out.splitlines() if x.strip().isdigit()]
    if not pid_list:
        console.print(f'[yellow]No valid PID found on port {port}[/yellow]')
        return
    cmds = [f'kill -9 {pid}' for pid in pid_list]
    if ir_dry_run:
        _print_ir_dry_run('Kill macOS process by port', details={'port': port, 'pids': ','.join(pid_list)}, commands=cmds)
        return
    _linux_execute_command_series('Kill macOS process by port', cmds, ir_dry_run=False)
    console.print(f'[green]Kill-by-port executed for port {port} (PIDs: {", ".join(pid_list)})[/green]')


def _mac_quarantine_log_path():
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    return outdir / 'macos_quarantine_log.jsonl'


def _mac_quarantine_file(ir_dry_run=False):
    src = console.input('File path to quarantine: ').strip()
    if not src:
        console.print('[red]No file path provided[/red]')
        return
    src_path = Path(src)
    if not src_path.exists():
        console.print('[red]File not found[/red]')
        return
    qdir = Path('outputs') / 'quarantine_macos'
    qdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    dst = qdir / f'{src_path.name}.{ts}.quarantine'
    cmds = [f'mv {shlex.quote(str(src_path))} {shlex.quote(str(dst))}']
    if ir_dry_run:
        _print_ir_dry_run('Quarantine macOS file', details={'source': str(src_path), 'destination': str(dst)}, commands=cmds)
        return
    res = run_command(cmds[0], shell=True)
    if res and isinstance(res, list) and '_error' in res[0]:
        console.print(f"[red]Quarantine failed: {res[0]['_error']}[/red]")
        return
    entry = {'timestamp': ts, 'source': str(src_path), 'quarantine_path': str(dst)}
    with _mac_quarantine_log_path().open('a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')
    console.print(f'[green]File quarantined to {dst}[/green]')


def _mac_restore_quarantined_file(ir_dry_run=False):
    logp = _mac_quarantine_log_path()
    if not logp.exists():
        console.print('[yellow]No macOS quarantine log found.[/yellow]')
        return
    entries = []
    for ln in logp.read_text(encoding='utf-8', errors='ignore').splitlines():
        try:
            entries.append(json.loads(ln))
        except Exception:
            continue
    if not entries:
        console.print('[yellow]No valid quarantine entries found.[/yellow]')
        return
    for i, e in enumerate(entries, 1):
        console.print(f"{i}. {e.get('quarantine_path')} -> {e.get('source')}")
    idx = console.input('Select entry number to restore: ').strip()
    if not idx.isdigit() or int(idx) < 1 or int(idx) > len(entries):
        console.print('[red]Invalid selection[/red]')
        return
    entry = entries[int(idx) - 1]
    src = entry.get('quarantine_path', '')
    dst = entry.get('source', '')
    if not src or not dst:
        console.print('[red]Invalid entry data[/red]')
        return
    cmd = f'mv {shlex.quote(src)} {shlex.quote(dst)}'
    if ir_dry_run:
        _print_ir_dry_run('Restore macOS quarantined file', details={'from': src, 'to': dst}, commands=[cmd])
        return
    res = run_command(cmd, shell=True)
    if res and isinstance(res, list) and '_error' in res[0]:
        console.print(f"[red]Restore failed: {res[0]['_error']}[/red]")
    else:
        console.print(f'[green]Restored file to {dst}[/green]')



def try_run_artifact(name):
    """Run artifact by name with simple fallbacks for missing columns or tables.

    Returns list of dict rows or list with _error/_output keys.
    """
    if (name in SPECIAL_ACTION_KEYS or name.startswith('macos_')) and name in globals() and callable(globals()[name]):
        try:
            return globals()[name]()
        except Exception as e:
            return [{'_error': str(e)}]

    # get primary result
    data = run_osquery(name)
    if data and isinstance(data, list) and isinstance(data[0], dict) and '_error' in data[0]:
        err = data[0]['_error']
        # handle no such column: try to remove offending column names from SQL and retry
        import re
        m = re.search(r"no such column: (\w+)", err)
        if m:
            badcol = m.group(1)
            sql = ARTIFACTS.get(name, {}).get('query')
            if sql:
                # remove occurrences of bad column (simple token replace)
                new_sql = re.sub(r'\b' + re.escape(badcol) + r'\b,?', '', sql, flags=re.IGNORECASE)
                # clean double commas and dangling commas before FROM or closing paren
                new_sql = re.sub(r',\s*,', ',', new_sql)
                new_sql = re.sub(r',\s+FROM', ' FROM', new_sql, flags=re.IGNORECASE)
                new_sql = re.sub(r'SELECT\s+,', 'SELECT ', new_sql, flags=re.IGNORECASE)
                new_sql = new_sql.replace('(,', '(').replace(',)', ')')
                new_sql = new_sql.strip()
                try:
                    retry = run_osquery(new_sql)
                    return retry
                except Exception:
                    return data
        # if table missing or other non-recoverable error, return original error
        return data
    # enrichment: if data has pid but not process name, try to fetch process names
    if isinstance(data, list) and data and isinstance(data[0], dict):
        rows = data
        if any('pid' in r for r in rows) and not any('name' in r or 'process_name' in r for r in rows):
            pids = sorted({str(r['pid']) for r in rows if 'pid' in r})
            # query process names
            pid_list = ','.join(pids)
            try:
                proc_rows = run_osquery(f"SELECT pid, name FROM processes WHERE pid IN ({pid_list});")
                name_map = {str(r.get('pid')): r.get('name') for r in proc_rows if isinstance(r, dict)}
                for r in rows:
                    if 'pid' in r:
                        r['process_name'] = name_map.get(str(r['pid']), '')
            except Exception:
                pass
        return data


def _extract_table_from_query(sql: str):
    m = re.search(r"FROM\s+([A-Za-z0-9_]+)", sql, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def _extract_select_columns(sql: str):
    m = re.search(r"SELECT\s+(.*?)\s+FROM", sql, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    cols = m.group(1)
    cols = cols.strip()
    if cols == '*':
        return ['*']
    parts = [c.strip() for c in cols.split(',') if c.strip()]
    clean = []
    for p in parts:
        # remove function calls and aliases
        p = re.sub(r"\s+AS\s+.*$", '', p, flags=re.IGNORECASE)
        # if 'table.col' take last part
        if '.' in p:
            p = p.split('.')[-1]
        # strip parentheses
        p = p.strip(' ()')
        clean.append(p)
    return clean


def diagnostic_report():
    console.print('\nRunning osquery compatibility diagnostic...')
    outdir = Path('outputs')
    outdir.mkdir(exist_ok=True)
    report = []
    for name, info in ARTIFACTS.items():
        sql = info.get('query')
        table = _extract_table_from_query(sql) if sql else None
        cols = _extract_select_columns(sql) if sql else None
        entry = {'artifact': name, 'table': table or '', 'available': False, 'missing_columns': [], 'notes': ''}
        # If table known, test for table existence
        if table:
            test = run_osquery(f'SELECT 1 FROM {table} LIMIT 1;')
            if test and isinstance(test, list) and isinstance(test[0], dict) and '_error' in test[0]:
                entry['available'] = False
                entry['notes'] = test[0]['_error']
                report.append(entry)
                continue
            else:
                entry['available'] = True
        # If columns known, test each column
        if cols:
            if cols == ['*']:
                # attempt to get a sample row to see keys
                sample = run_osquery(f'SELECT * FROM {table} LIMIT 1;') if table else run_osquery(sql + ' LIMIT 1;')
                if sample and isinstance(sample, list) and sample and isinstance(sample[0], dict):
                    entry['available_columns'] = list(sample[0].keys())
                else:
                    entry['available_columns'] = []
            else:
                avail = []
                missing = []
                for col in cols:
                    # skip empty
                    if not col:
                        continue
                    check_sql = f'SELECT {col} FROM {table} LIMIT 1;' if table else f'SELECT {col} LIMIT 1;'
                    res = run_osquery(check_sql)
                    if res and isinstance(res, list) and isinstance(res[0], dict) and '_error' in res[0]:
                        err = res[0]['_error']
                        if 'no such column' in err.lower():
                            missing.append(col)
                        else:
                            # other error: record note
                            entry['notes'] = err
                    else:
                        avail.append(col)
                entry['available_columns'] = avail
                entry['missing_columns'] = missing
        else:
            # fallback: try running stored query
            res = run_osquery((sql + ' LIMIT 1;') if sql and 'limit' not in sql.lower() else sql)
            if res and isinstance(res, list) and res and isinstance(res[0], dict):
                entry['available_columns'] = list(res[0].keys())
            else:
                entry['available_columns'] = []
            if res and isinstance(res, list) and res and isinstance(res[0], dict) and '_error' in res[0]:
                entry['notes'] = res[0]['_error']
        report.append(entry)

    # Save JSON and CSV
    out_json = outdir / 'osquery_diagnostic.json'
    out_csv = outdir / 'osquery_diagnostic.csv'
    with out_json.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    # CSV: flatten available_columns and missing_columns
    with out_csv.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['artifact', 'table', 'available', 'available_columns', 'missing_columns', 'notes'])
        for r in report:
            writer.writerow([r.get('artifact'), r.get('table'), r.get('available'), ';'.join(r.get('available_columns') or []), ';'.join(r.get('missing_columns') or []), r.get('notes')])

    console.print(f'Diagnostic saved: {out_json} and {out_csv}')
    # update available artifacts global
    global available_artifacts
    available_artifacts = {entry['artifact'] for entry in report if entry.get('available')}
    return report


def readiness_check():
    """Run diagnostic and print summary of supported vs unsupported artifacts."""
    if PLATFORM_RUNTIME.os_key == 'linux':
        return linux_readiness_report()
    if PLATFORM_RUNTIME.os_key == 'macos':
        return macos_readiness_report()

    report = diagnostic_report()
    supported = [r['artifact'] for r in report if r.get('available')]
    unsupported = [r['artifact'] for r in report if not r.get('available')]
    console.print('\n[bold]Readiness Summary[/bold]')
    console.print(f'Supported artifacts: {len(supported)}')
    console.print(f'Unsupported artifacts: {len(unsupported)}')
    if unsupported:
        console.print('[yellow]' + ', '.join(unsupported) + '[/yellow]')
    console.print('Diagnostic report files created.')
    return report

def detect_browsers():
    """Return dict of browsers and available profile history paths."""
    browsers = {}

    def _linux_detect_installation(browser_name, binary_names, extra_paths=None):
        if PLATFORM_RUNTIME.os_key != 'linux':
            return []
        found = []
        for binary in binary_names:
            binary_path = shutil.which(binary)
            if binary_path:
                found.append(binary_path)
        for path in extra_paths or []:
            try:
                if Path(path).exists():
                    found.append(str(path))
            except Exception:
                continue
        # de-duplicate while keeping order
        seen = set()
        unique = []
        for item in found:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    def _history_from_profile_dir(profile_dir):
        candidates = [
            profile_dir / 'History',
            profile_dir / 'history',
            profile_dir / 'Default' / 'History',
            profile_dir / 'Default' / 'history',
        ]
        for c in candidates:
            if c.exists() and c.is_file():
                return c
        return None

    def _collect_chromium_profiles(base_path):
        profiles = []
        if not base_path.exists():
            return profiles

        try:
            children = [p for p in base_path.iterdir() if p.is_dir()]
        except Exception:
            children = []

        for p in children:
            if not p.is_dir():
                continue
            looks_like_profile = (
                p.name == 'Default'
                or p.name.startswith('Profile')
                or (p / 'History').exists()
                or (p / 'Network' / 'Cookies').exists()
                or (p / 'Extensions').exists()
            )
            if looks_like_profile:
                profiles.append({'name': p.name, 'history': _history_from_profile_dir(p), 'profile_dir': p})

        if not profiles:
            if any((base_path / marker).exists() for marker in ('History', 'Default', 'Extensions', 'Network')):
                profiles.append({'name': 'Default', 'history': _history_from_profile_dir(base_path), 'profile_dir': base_path})

        return profiles

    def _collect_firefox_profiles(base_path):
        profiles = []
        if not base_path.exists():
            return profiles

        try:
            candidates = [p for p in base_path.iterdir() if p.is_dir()]
        except Exception:
            candidates = []

        for p in candidates:
            hist = p / 'places.sqlite'
            if hist.exists() or p.name.endswith('.default') or p.name.endswith('.default-release'):
                profiles.append({'name': p.name, 'history': hist if hist.exists() else None, 'profile_dir': p})

        return profiles

    def _merge_profiles(existing, incoming):
        seen = {str(Path(x.get('profile_dir')).resolve()) for x in existing if x.get('profile_dir')}
        for item in incoming:
            pdir = item.get('profile_dir')
            if not pdir:
                continue
            key = str(Path(pdir).resolve())
            if key in seen:
                continue
            seen.add(key)
            existing.append(item)
        return existing
    if PLATFORM_RUNTIME.os_key in ('windows', 'windows-server'):
        local = os.getenv('LOCALAPPDATA', '')
        appd = os.getenv('APPDATA', '')

        win_map = {
            'chrome': Path(local) / 'Google/Chrome/User Data',
            'edge': Path(local) / 'Microsoft/Edge/User Data',
            'brave': Path(local) / 'BraveSoftware/Brave-Browser/User Data',
            'vivaldi': Path(local) / 'Vivaldi/User Data',
        }
        for name, base in win_map.items():
            profiles = _collect_chromium_profiles(base)
            if profiles:
                browsers[name] = profiles

        opera_base = Path(appd) / 'Opera Software/Opera Stable'
        if opera_base.exists():
            hist = opera_base / 'History'
            browsers['opera'] = [{'name': 'Default', 'history': hist if hist.exists() else None, 'profile_dir': opera_base}]
        firefox_base = Path(appd) / 'Mozilla/Firefox/Profiles'
        if firefox_base.exists():
            profiles = []
            for p in firefox_base.iterdir():
                if p.is_dir():
                    hist = p / 'places.sqlite'
                    profiles.append({'name': p.name, 'history': hist if hist.exists() else None, 'profile_dir': p})
            if profiles:
                browsers['firefox'] = profiles

    elif PLATFORM_RUNTIME.os_key == 'linux':
        # Build candidate home directories. This handles sudo/root runs where
        # HOME may point to /root while browser profiles live under /home/<user>.
        home_candidates = []
        home_env = os.getenv('HOME', '')
        if home_env:
            home_candidates.append(Path(home_env))

        sudo_user = os.getenv('SUDO_USER', '').strip()
        if sudo_user:
            home_candidates.append(Path('/home') / sudo_user)

        home_root = Path('/home')
        if home_root.exists():
            try:
                for p in home_root.iterdir():
                    if p.is_dir():
                        home_candidates.append(p)
            except Exception:
                pass

        # de-duplicate and keep existing paths only
        seen_homes = set()
        homes = []
        for h in home_candidates:
            key = str(h)
            if key in seen_homes:
                continue
            seen_homes.add(key)
            if h.exists():
                homes.append(h)

        for home in homes:
            xdg_config = Path(os.getenv('XDG_CONFIG_HOME', str(home / '.config')))
            linux_map = {
                'chrome': [
                    xdg_config / 'google-chrome',
                    xdg_config / 'google-chrome-beta',
                    xdg_config / 'google-chrome-unstable',
                    home / '.config/google-chrome',
                    home / '.config/google-chrome-beta',
                    home / '.config/google-chrome-unstable',
                    home / 'snap/google-chrome/current/.config/google-chrome',
                    home / 'snap/google-chrome/common/.config/google-chrome',
                    home / '.var/app/com.google.Chrome/config/google-chrome',
                ],
                'chromium': [
                    xdg_config / 'chromium',
                    home / '.config/chromium',
                    home / 'snap/chromium/common/chromium',
                    home / 'snap/chromium/current/chromium',
                    home / '.var/app/org.chromium.Chromium/config/chromium',
                ],
                'edge': [
                    xdg_config / 'microsoft-edge',
                    xdg_config / 'microsoft-edge-beta',
                    xdg_config / 'microsoft-edge-dev',
                    home / '.config/microsoft-edge',
                    home / '.config/microsoft-edge-beta',
                    home / '.config/microsoft-edge-dev',
                    home / 'snap/microsoft-edge/current/.config/microsoft-edge',
                    home / 'snap/microsoft-edge/common/.config/microsoft-edge',
                    home / '.var/app/com.microsoft.Edge/config/microsoft-edge',
                ],
                'brave': [
                    xdg_config / 'BraveSoftware/Brave-Browser',
                    xdg_config / 'BraveSoftware/Brave-Browser-Beta',
                    xdg_config / 'BraveSoftware/Brave-Browser-Nightly',
                    home / '.config/BraveSoftware/Brave-Browser',
                    home / '.config/BraveSoftware/Brave-Browser-Beta',
                    home / '.config/BraveSoftware/Brave-Browser-Nightly',
                    home / 'snap/brave/current/.config/BraveSoftware/Brave-Browser',
                    home / 'snap/brave/common/.config/BraveSoftware/Brave-Browser',
                    home / '.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser',
                ],
                'vivaldi': [
                    xdg_config / 'vivaldi',
                    home / '.config/vivaldi',
                    home / '.var/app/com.vivaldi.Vivaldi/config/vivaldi',
                ],
            }

            for name, bases in linux_map.items():
                collected = browsers.get(name, [])
                for base in bases:
                    _merge_profiles(collected, _collect_chromium_profiles(base))
                if collected:
                    browsers[name] = collected

            # Opera can appear in multiple profile roots depending on package source.
            opera_bases = [
                xdg_config / 'opera',
                home / '.config/opera',
                home / '.config/opera-beta',
                home / '.config/opera-developer',
            ]
            opera_profiles = browsers.get('opera', [])
            for base in opera_bases:
                if not base.exists():
                    continue
                # Prefer explicit Default profile if present, otherwise use base as profile root.
                default_profile = base / 'Default'
                if default_profile.exists() and default_profile.is_dir():
                    _merge_profiles(opera_profiles, [{'name': 'Default', 'history': _history_from_profile_dir(default_profile), 'profile_dir': default_profile}])
                else:
                    _merge_profiles(opera_profiles, [{'name': 'Default', 'history': _history_from_profile_dir(base), 'profile_dir': base}])
            if opera_profiles:
                browsers['opera'] = opera_profiles

            firefox_bases = [
                home / '.mozilla/firefox',
                home / 'snap/firefox/common/.mozilla/firefox',
                home / '.var/app/org.mozilla.firefox/.mozilla/firefox',
            ]
            firefox_profiles = browsers.get('firefox', [])
            for base in firefox_bases:
                _merge_profiles(firefox_profiles, _collect_firefox_profiles(base))
            if firefox_profiles:
                browsers['firefox'] = firefox_profiles

        # Fallback: if Chromium-family browsers are still missing, do a bounded
        # recursive scan for known signatures under candidate homes.
        chromium_keys = {'chrome', 'chromium', 'edge', 'brave', 'vivaldi', 'opera'}
        chromium_detected = [k for k in chromium_keys if k in browsers]
        if not chromium_detected or len(browsers) <= 1:
            signature_hits = []
            signature_names = {'History', 'places.sqlite', 'Cookies', 'extensions.json', 'Local State'}
            for home in homes:
                try:
                    for p in home.rglob('*'):
                        if p.name in signature_names:
                            signature_hits.append(p)
                            if len(signature_hits) >= 200:
                                break
                    if len(signature_hits) >= 200:
                        break
                except Exception:
                    continue

            # Infer browser profile roots from signatures.
            for sig in signature_hits:
                s = str(sig).lower()
                profile_dir = None
                browser_name = None

                if 'mozilla/firefox' in s or 'org.mozilla.firefox' in s:
                    browser_name = 'firefox'
                    profile_dir = sig.parent
                    if sig.name == 'extensions.json':
                        profile_dir = sig.parent
                    if sig.name == 'places.sqlite':
                        profile_dir = sig.parent
                elif any(k in s for k in ['google-chrome', 'chromium', 'microsoft-edge', 'brave-browser', 'vivaldi', 'opera']):
                    parts = sig.parts
                    if sig.name == 'Local State':
                        profile_dir = sig.parent / 'Default' if (sig.parent / 'Default').exists() else sig.parent
                    for idx in range(len(parts) - 1, -1, -1):
                        if parts[idx] in ('Default',) or parts[idx].startswith('Profile'):
                            profile_dir = Path(*parts[:idx + 1])
                            break
                    if not profile_dir:
                        profile_dir = sig.parent

                    if 'google-chrome' in s:
                        browser_name = 'chrome'
                    elif 'chromium' in s:
                        browser_name = 'chromium'
                    elif 'microsoft-edge' in s:
                        browser_name = 'edge'
                    elif 'brave-browser' in s or 'bravesoftware' in s:
                        browser_name = 'brave'
                    elif 'vivaldi' in s:
                        browser_name = 'vivaldi'
                    elif 'opera' in s:
                        browser_name = 'opera'

                if browser_name and profile_dir and profile_dir.exists():
                    existing = browsers.get(browser_name, [])
                    _merge_profiles(existing, [{
                        'name': profile_dir.name if (profile_dir.name == 'Default' or profile_dir.name.startswith('Profile')) else 'Default',
                        'history': _history_from_profile_dir(profile_dir),
                        'profile_dir': profile_dir,
                    }])
                    if existing:
                        browsers[browser_name] = existing

    elif PLATFORM_RUNTIME.os_key == 'macos':
        home = Path(os.getenv('HOME', ''))
        mac_map = {
            'chrome': home / 'Library/Application Support/Google/Chrome',
            'edge': home / 'Library/Application Support/Microsoft Edge',
            'brave': home / 'Library/Application Support/BraveSoftware/Brave-Browser',
            'vivaldi': home / 'Library/Application Support/Vivaldi',
            'opera': home / 'Library/Application Support/com.operasoftware.Opera',
            'arc': home / 'Library/Application Support/Arc/User Data',
        }
        for name, base in mac_map.items():
            profiles = _collect_chromium_profiles(base)
            if profiles:
                browsers[name] = profiles

        firefox_base = home / 'Library/Application Support/Firefox/Profiles'
        if firefox_base.exists():
            profiles = _collect_firefox_profiles(firefox_base)
            if profiles:
                browsers['firefox'] = profiles

        safari_dir = home / 'Library/Safari'
        safari_history = safari_dir / 'History.db'
        if safari_dir.exists():
            browsers['safari'] = [{
                'name': 'Default',
                'history': safari_history if safari_history.exists() else None,
                'profile_dir': safari_dir,
            }]

    return browsers


def _linux_browser_installation_inventory():
    """Return best-effort installation hints for Linux browsers."""
    if PLATFORM_RUNTIME.os_key != 'linux':
        return {}

    home = Path(os.getenv('HOME', ''))
    xdg_config = Path(os.getenv('XDG_CONFIG_HOME', str(home / '.config'))) if home else Path('')

    def _detect_installation(binary_names, extra_paths=None):
        found = []
        for binary in binary_names:
            binary_path = shutil.which(binary)
            if binary_path:
                found.append(binary_path)

        for path in extra_paths or []:
            try:
                if Path(path).exists():
                    found.append(str(path))
            except Exception:
                continue

        seen = set()
        unique = []
        for item in found:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    inventory = {
        'chrome': _detect_installation(['google-chrome', 'google-chrome-stable', 'google-chrome-beta', 'google-chrome-unstable'], [
            '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/snap/bin/google-chrome', '/snap/bin/google-chrome-stable',
            home / '.config/google-chrome', home / '.config/google-chrome-beta', home / '.config/google-chrome-unstable',
            xdg_config / 'google-chrome', xdg_config / 'google-chrome-beta', xdg_config / 'google-chrome-unstable',
        ]),
        'chromium': _detect_installation(['chromium', 'chromium-browser'], [
            '/usr/bin/chromium', '/usr/bin/chromium-browser', '/snap/bin/chromium',
            home / '.config/chromium', xdg_config / 'chromium', home / 'snap/chromium/common/chromium', home / 'snap/chromium/current/chromium',
        ]),
        'edge': _detect_installation(['microsoft-edge', 'microsoft-edge-stable', 'microsoft-edge-beta', 'microsoft-edge-dev'], [
            '/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable', '/snap/bin/microsoft-edge',
            home / '.config/microsoft-edge', home / '.config/microsoft-edge-beta', home / '.config/microsoft-edge-dev',
            xdg_config / 'microsoft-edge', xdg_config / 'microsoft-edge-beta', xdg_config / 'microsoft-edge-dev',
        ]),
        'brave': _detect_installation(['brave-browser', 'brave'], [
            '/usr/bin/brave-browser', '/snap/bin/brave', '/snap/bin/brave-browser',
            home / '.config/BraveSoftware/Brave-Browser', home / '.config/BraveSoftware/Brave-Browser-Beta', home / '.config/BraveSoftware/Brave-Browser-Nightly',
            xdg_config / 'BraveSoftware/Brave-Browser', xdg_config / 'BraveSoftware/Brave-Browser-Beta', xdg_config / 'BraveSoftware/Brave-Browser-Nightly',
        ]),
        'vivaldi': _detect_installation(['vivaldi', 'vivaldi-stable'], [
            '/usr/bin/vivaldi', '/usr/bin/vivaldi-stable', '/snap/bin/vivaldi',
            home / '.config/vivaldi', xdg_config / 'vivaldi',
        ]),
        'opera': _detect_installation(['opera', 'opera-stable', 'opera-beta', 'opera-developer'], [
            '/usr/bin/opera', '/usr/bin/opera-stable', '/snap/bin/opera',
            home / '.config/opera', home / '.config/opera-beta', home / '.config/opera-developer',
            xdg_config / 'opera', xdg_config / 'opera-beta', xdg_config / 'opera-developer',
        ]),
        'firefox': _detect_installation(['firefox'], [
            '/usr/bin/firefox', '/snap/bin/firefox',
            home / '.mozilla/firefox', home / 'snap/firefox/common/.mozilla/firefox', home / '.var/app/org.mozilla.firefox/.mozilla/firefox',
        ]),
    }
    return inventory


def collect_browser_extensions_inventory():
    """Collect browser extensions/add-ons from profile files/directories with diagnostics."""
    browsers = detect_browsers()
    rows = []
    browser_ext_status = {}  # Track which browsers have extensions
    safari_privacy_warned = {'shown': False}

    def _warn_safari_privacy_once():
        if safari_privacy_warned.get('shown'):
            return
        console.print('[yellow]Safari extension store exists but could not be opened. Check macOS Privacy & Security -> Full Disk Access and enable it for Python (and Terminal/iTerm/VS Code), then restart and retry.[/yellow]')
        safari_privacy_warned['shown'] = True

    for browser, profiles in browsers.items():
        browser_ext_status[browser] = {'profiles_checked': 0, 'extensions_found': 0}
        
        for prof in profiles:
            profile_name = prof.get('name', 'Default')
            profile_dir = prof.get('profile_dir')
            if not profile_dir:
                continue
            profile_dir = Path(profile_dir)
            browser_ext_status[browser]['profiles_checked'] += 1

            if browser.lower() in ('chrome', 'chromium', 'edge', 'brave', 'opera', 'vivaldi'):
                # Opera paths vary by package/profile layout; try both common variants.
                if browser.lower() == 'opera':
                    ext_candidates = [
                        profile_dir / 'Extensions',
                        profile_dir / 'Default' / 'Extensions',
                    ]
                else:
                    ext_candidates = [profile_dir / 'Extensions']

                ext_root = next((p for p in ext_candidates if p.exists()), None)
                if not ext_root:
                    continue
                
                try:
                    ext_dirs = [d for d in ext_root.iterdir() if d.is_dir()]
                except Exception:
                    ext_dirs = []
                
                for ext_id_dir in ext_dirs:
                    version_dirs = [d for d in ext_id_dir.iterdir() if d.is_dir()]
                    if not version_dirs:
                        rows.append({
                            'browser': browser,
                            'profile': profile_name,
                            'extension_id': ext_id_dir.name,
                            'name': ext_id_dir.name,
                            'version': '',
                            'permissions': '',
                            'host_permissions': '',
                            'source': str(ext_id_dir),
                        })
                        browser_ext_status[browser]['extensions_found'] += 1
                        continue
                    
                    for vdir in sorted(version_dirs, reverse=True):
                        manifest = vdir / 'manifest.json'
                        if not manifest.exists():
                            continue
                        try:
                            with open(manifest, 'r', encoding='utf-8') as f:
                                m = json.load(f)
                            rows.append({
                                'browser': browser,
                                'profile': profile_name,
                                'extension_id': ext_id_dir.name,
                                'name': m.get('name', ext_id_dir.name),
                                'version': m.get('version', ''),
                                'permissions': ';'.join(m.get('permissions', []) or []),
                                'host_permissions': ';'.join(m.get('host_permissions', []) or []),
                                'source': str(manifest),
                            })
                            browser_ext_status[browser]['extensions_found'] += 1
                        except Exception:
                            rows.append({
                                'browser': browser,
                                'profile': profile_name,
                                'extension_id': ext_id_dir.name,
                                'name': ext_id_dir.name,
                                'version': vdir.name,
                                'permissions': '',
                                'host_permissions': '',
                                'source': str(manifest),
                            })
                            browser_ext_status[browser]['extensions_found'] += 1
                        break

            elif browser.lower() == 'safari':
                safari_ext_roots = [
                    profile_dir / 'Extensions',
                    profile_dir / 'Safari' / 'Extensions',
                    Path.home() / 'Library' / 'Safari' / 'Extensions',
                    Path.home() / 'Library' / 'Containers' / 'com.apple.Safari' / 'Data' / 'Library' / 'Safari' / 'Extensions',
                ]
                ext_root = next((p for p in safari_ext_roots if p.exists()), None)
                if not ext_root:
                    continue

                try:
                    ext_items = [item for item in ext_root.rglob('*') if item.is_file() and item.suffix.lower() in ('.safariextz', '.appex', '.plist')]
                except Exception as e:
                    err_l = str(e).lower()
                    if PLATFORM_RUNTIME.os_key == 'macos' and (
                        'operation not permitted' in err_l
                        or 'permission denied' in err_l
                        or 'authorization denied' in err_l
                    ):
                        _warn_safari_privacy_once()
                    ext_items = []

                for item in ext_items:
                    extension_name = item.stem
                    extension_id = item.stem
                    if item.suffix.lower() == '.plist':
                        try:
                            import plistlib
                            with open(item, 'rb') as f:
                                plist_data = plistlib.load(f)
                            extension_name = plist_data.get('CFBundleDisplayName') or plist_data.get('CFBundleName') or extension_name
                            extension_id = plist_data.get('CFBundleIdentifier', extension_id)
                        except Exception:
                            pass
                    rows.append({
                        'browser': browser,
                        'profile': profile_name,
                        'extension_id': extension_id,
                        'name': extension_name,
                        'version': '',
                        'permissions': '',
                        'host_permissions': '',
                        'source': str(item),
                    })
                    browser_ext_status[browser]['extensions_found'] += 1

            elif browser.lower() == 'firefox':
                ext_json = profile_dir / 'extensions.json'
                if ext_json.exists():
                    try:
                        with open(ext_json, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        addons = data.get('addons', []) if isinstance(data, dict) else []
                        for a in addons:
                            rows.append({
                                'browser': browser,
                                'profile': profile_name,
                                'extension_id': a.get('id', ''),
                                'name': a.get('defaultLocale', {}).get('name', a.get('name', a.get('id', ''))),
                                'version': a.get('version', ''),
                                'permissions': ';'.join(a.get('userPermissions', {}).get('permissions', []) or []),
                                'host_permissions': ';'.join(a.get('userPermissions', {}).get('origins', []) or []),
                                'source': str(ext_json),
                            })
                            browser_ext_status[browser]['extensions_found'] += 1
                    except Exception:
                        pass
                else:
                    ext_dir = profile_dir / 'extensions'
                    if ext_dir.exists():
                        try:
                            ext_items = [item for item in ext_dir.iterdir()]
                        except Exception:
                            ext_items = []
                        
                        for item in ext_items:
                            if item.is_file() and item.suffix.lower() in ('.xpi', '.json'):
                                rows.append({
                                    'browser': browser,
                                    'profile': profile_name,
                                    'extension_id': item.stem,
                                    'name': item.stem,
                                    'version': '',
                                    'permissions': '',
                                    'host_permissions': '',
                                    'source': str(item),
                                })
                                browser_ext_status[browser]['extensions_found'] += 1

    return rows


def dump_history_to_csv(history_path, profile_dir=None, browser_name='unknown', outpath=None):
    """Dump browser history from History/History DB file or fallback to alternative locations."""
    import pandas as pd
    import sqlite3
    import shutil

    def _run_cmd_timeout(cmd_list, timeout_sec=20):
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout_sec,
            )
            out = (proc.stdout or '').strip()
            err = (proc.stderr or '').strip()
            if proc.returncode != 0:
                return '', err or out or f'returncode {proc.returncode}'
            return out, ''
        except subprocess.TimeoutExpired:
            return '', f'timeout after {timeout_sec}s'
        except Exception as e:
            return '', str(e)
    
    # Find the actual history database file
    history_file = None
    if history_path and Path(history_path).exists() and Path(history_path).is_file():
        history_file = Path(history_path)
    elif history_path and Path(history_path).exists() and Path(history_path).is_dir() and not profile_dir:
        profile_dir = Path(history_path)
    elif profile_dir:
        # Try alternative locations
        alternatives = [
            Path(profile_dir) / 'History',
            Path(profile_dir) / 'Default' / 'History',
            Path(profile_dir) / 'History.db',
            Path(profile_dir) / 'history.db',
            Path(profile_dir) / 'browsing_history.db',
        ]
        for alt in alternatives:
            if alt.exists() and alt.is_file():
                history_file = alt
                break
    
    if not history_file:
        return False, 'History database not found in standard or alternative locations'

    def _safari_plist_history_fallback(destination):
        plist_candidates = [
            Path.home() / 'Library/Safari/Bookmarks.plist',
            Path.home() / 'Library/Safari/RecentlyClosedTabs.plist',
            Path.home() / 'Library/Safari/Downloads.plist',
            Path.home() / 'Library/Safari/LastSession.plist',
            Path.home() / 'Library/Safari/TopSites.plist',
        ]

        def _walk(obj):
            if isinstance(obj, dict):
                yield obj
                for v in obj.values():
                    yield from _walk(v)
            elif isinstance(obj, list):
                for i in obj:
                    yield from _walk(i)

        rows_local = []
        readable_plists = []
        for plist in plist_candidates:
            if not plist.exists():
                continue
            raw, _ = _run_cmd_timeout(['plutil', '-convert', 'json', '-o', '-', str(plist)], timeout_sec=12)
            if not raw:
                continue
            readable_plists.append(plist.name)
            try:
                parsed = json.loads(raw)
            except Exception:
                continue
            for node in _walk(parsed):
                url = node.get('URL') or node.get('url') or node.get('lastVisitedURLString')
                title = node.get('title') or node.get('Title') or node.get('displayTitle') or ''
                ts = node.get('dateClosed') or node.get('lastVisitedDate') or node.get('visitTime') or ''
                if url:
                    rows_local.append({'visit_time': ts, 'url': url, 'title': title, 'source': plist.name})
                elif title and plist.name.lower().endswith('bookmarks.plist'):
                    rows_local.append({'visit_time': ts, 'url': '', 'title': title, 'source': plist.name})

        recent_searches = run_command('defaults read com.apple.Safari RecentSearchStrings 2>/dev/null', shell=True)
        rs_out = recent_searches[0].get('_output', '').strip() if recent_searches and isinstance(recent_searches, list) else ''
        if rs_out:
            for ln in rs_out.splitlines():
                term = ln.strip().strip('"').strip(',').strip('()')
                if term and term not in ('{', '}', '(', ')'):
                    rows_local.append({'visit_time': '', 'url': '', 'title': f'recent_search: {term}', 'source': 'defaults_recent_search'})

        if not rows_local and readable_plists:
            for name in readable_plists:
                rows_local.append({'visit_time': '', 'url': '', 'title': 'plist readable but no URL rows parsed', 'source': name})

        if rows_local and destination:
            import csv as _csv
            with open(destination, 'w', newline='', encoding='utf-8') as f:
                writer = _csv.DictWriter(f, fieldnames=['source', 'visit_time', 'url', 'title'])
                writer.writeheader()
                for r in rows_local[:5000]:
                    writer.writerow(r)
            return True
        return False

    if browser_name.lower() == 'safari':
        q = (
            "SELECT datetime(visit_time+978307200, 'unixepoch', 'localtime') AS visit_time, "
            'history_items.url AS url, history_items.title AS title '
            'FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id '
            'ORDER BY visit_time DESC LIMIT 5000;'
        )
        # Prefer sqlite3 CLI for Safari due occasional Python sqlite open failures on macOS privacy-managed DB files.
        raw, cli_err = _run_cmd_timeout(
            ['sqlite3', '-readonly', '-header', '-csv', str(history_file), q],
            timeout_sec=18,
        )
        if raw and outpath:
            Path(outpath).write_text(raw + ('\n' if not raw.endswith('\n') else ''), encoding='utf-8')
            return True, ''

        # Fallback: copy DB to temporary file and query the copy.
        if outpath:
            tmp_copy = Path(outpath).with_suffix('.safari.tmp.db')
            try:
                shutil.copy2(str(history_file), str(tmp_copy))
            except Exception:
                tmp_copy = None
            if tmp_copy and tmp_copy.exists():
                raw2, _ = _run_cmd_timeout(
                    ['sqlite3', '-readonly', '-header', '-csv', str(tmp_copy), q],
                    timeout_sec=18,
                )
                try:
                    tmp_copy.unlink()
                except Exception:
                    pass
                if raw2:
                    Path(outpath).write_text(raw2 + ('\n' if not raw2.endswith('\n') else ''), encoding='utf-8')
                    return True, ''

        if 'authorization denied' in (cli_err or '').lower():
            if _safari_plist_history_fallback(outpath):
                return True, ''
            return False, 'Safari history access is blocked by macOS privacy controls and no readable fallback rows were found'
        return False, cli_err or 'Unable to read Safari history database (grant Full Disk Access to Terminal/Python and retry)'
    
    try:
        # copy database to avoid locked file if browser open
        tmp = Path(outpath).with_suffix('.tmp.db') if outpath else None
        if tmp:
            try:
                shutil.copy2(str(history_file), str(tmp))
                db_to_open = tmp
            except Exception:
                db_to_open = history_file
        else:
            db_to_open = history_file
        
        conn = None
        if browser_name.lower() == 'safari':
            try:
                conn = sqlite3.connect(f'{Path(db_to_open).resolve().as_uri()}?mode=ro', uri=True)
            except Exception:
                conn = None
        if conn is None:
            conn = sqlite3.connect(str(db_to_open))
        # for Chrome/Edge/Brave/Opera, urls table; for Firefox, moz_places
        hpath = str(history_file).lower()
        if 'places.sqlite' in hpath:
            df = pd.read_sql_query('SELECT * FROM moz_places;', conn)
        elif hpath.endswith('history.db') or browser_name.lower() == 'safari':
            df = pd.read_sql_query(
                "SELECT datetime(visit_time+978307200, 'unixepoch', 'localtime') AS visit_time, "
                'history_items.url AS url, history_items.title AS title '
                'FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id '
                'ORDER BY visit_time DESC;',
                conn,
            )
        else:
            df = pd.read_sql_query('SELECT * FROM urls;', conn)
        
        if outpath:
            df.to_csv(outpath, index=False)
        
        conn.close()
        try:
            if tmp and tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        return True, ''
    except Exception as e:
        if browser_name.lower() == 'safari':
            try:
                q = (
                    "SELECT datetime(visit_time+978307200, 'unixepoch', 'localtime'), "
                    'history_items.url, history_items.title '
                    'FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id '
                    'ORDER BY visit_time DESC LIMIT 1000;'
                )
                cmd = f'sqlite3 -header -csv {shlex.quote(str(history_file))} {shlex.quote(q)}'
                res = run_command(cmd, shell=True)
                raw = res[0].get('_output', '') if res and isinstance(res, list) else ''
                if raw and outpath:
                    Path(outpath).write_text(raw + ('\n' if not raw.endswith('\n') else ''), encoding='utf-8')
                    return True, ''
            except Exception:
                pass
        return False, str(e)


def dump_browser_downloads_to_csv(db_path, browser_name, profile_name, outpath):
    """Dump browser download-like records using native download tables when possible.
    
    db_path can be either a History file path or a profile directory path.
    """
    import pandas as pd
    import sqlite3
    import shutil

    def _run_cmd_timeout(cmd_list, timeout_sec=18):
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout_sec,
            )
            out = (proc.stdout or '').strip()
            err = (proc.stderr or '').strip()
            if proc.returncode != 0:
                return '', err or out or f'returncode {proc.returncode}'
            return out, ''
        except subprocess.TimeoutExpired:
            return '', f'timeout after {timeout_sec}s'
        except Exception as e:
            return '', str(e)

    def _find_history_db(path):
        """Find history database from path (which could be file or directory)."""
        path = Path(path)
        if path.is_file():
            return path
        # If path is a directory, look for History file
        candidates = [
            path / 'History',
            path / 'Default' / 'History',
            path / 'History.db',
            path / 'history.db',
            path / 'browsing_history.db',
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def _table_exists(conn, table_name):
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
        return cur.fetchone() is not None

    def _manual_download_snapshot(destination):
        rows = []
        download_dirs = []
        home_dir = Path.home()
        download_dirs.append(home_dir / 'Downloads')
        env_home = os.getenv('HOME', '').strip()
        if env_home:
            download_dirs.append(Path(env_home) / 'Downloads')
        users_root = Path('/Users')
        if users_root.exists():
            try:
                for user_dir in users_root.iterdir():
                    if user_dir.is_dir():
                        download_dirs.append(user_dir / 'Downloads')
            except Exception:
                pass

        seen = set()
        unique_dirs = []
        for d in download_dirs:
            key = str(d)
            if key in seen:
                continue
            seen.add(key)
            unique_dirs.append(d)

        for base in unique_dirs:
            if not base.exists() or not base.is_dir():
                continue
            try:
                for item in base.iterdir():
                    if len(rows) >= 500:
                        break
                    try:
                        st = item.stat()
                        rows.append({
                            'browser': browser_name,
                            'profile': profile_name,
                            'source': 'downloads_folder_snapshot',
                            'path': str(item),
                            'title': item.name,
                            'size': st.st_size,
                            'mtime': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        })
                    except Exception:
                        continue
            except Exception:
                continue
            if len(rows) >= 500:
                break

        if rows and destination:
            import csv as _csv
            with open(destination, 'w', newline='', encoding='utf-8') as f:
                writer = _csv.DictWriter(f, fieldnames=['browser', 'profile', 'source', 'path', 'title', 'size', 'mtime'])
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
            return True, ''
        return False, 'No download records found'

    def _fallback_download_rows(conn, source_table):
        if source_table == 'moz_places':
            sql = (
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places "
                "WHERE lower(url) LIKE '%.zip' OR lower(url) LIKE '%.exe' OR lower(url) LIKE '%.msi' "
                "OR lower(url) LIKE '%.deb' OR lower(url) LIKE '%.rpm' OR lower(url) LIKE '%.tar.gz' "
                "OR lower(url) LIKE '%.tgz' OR lower(url) LIKE '%.dmg' OR lower(url) LIKE '%.pkg' "
                "OR lower(url) LIKE '%.sh' OR lower(url) LIKE '%.py' OR lower(url) LIKE '%download%' "
                "OR lower(title) LIKE '%download%' LIMIT 500;"
            )
        else:
            sql = (
                "SELECT url, title, visit_count, last_visit_time "
                "FROM urls "
                "WHERE lower(url) LIKE '%.zip' OR lower(url) LIKE '%.exe' OR lower(url) LIKE '%.msi' "
                "OR lower(url) LIKE '%.deb' OR lower(url) LIKE '%.rpm' OR lower(url) LIKE '%.tar.gz' "
                "OR lower(url) LIKE '%.tgz' OR lower(url) LIKE '%.dmg' OR lower(url) LIKE '%.pkg' "
                "OR lower(url) LIKE '%.sh' OR lower(url) LIKE '%.py' OR lower(url) LIKE '%download%' "
                "OR lower(title) LIKE '%download%' LIMIT 500;"
            )
        try:
            return pd.read_sql_query(sql, conn)
        except Exception:
            return pd.DataFrame([])

    # Find the actual history database file
    history_file = _find_history_db(db_path)
    if not history_file:
        return False, 'History database not found (history may not have been recorded)'

    if browser_name.lower() == 'safari':
        q = (
            "SELECT datetime(history_visits.visit_time+978307200, 'unixepoch', 'localtime') AS visit_time, "
            'history_items.url AS url, history_items.title AS title '
            'FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id '
            'WHERE lower(history_items.url) LIKE "%.zip" OR lower(history_items.url) LIKE "%.dmg" '
            'OR lower(history_items.url) LIKE "%.pkg" OR lower(history_items.url) LIKE "%download%" '
            'OR lower(history_items.title) LIKE "%download%" '
            'ORDER BY history_visits.visit_time DESC LIMIT 500;'
        )
        raw, serr = _run_cmd_timeout(
            ['sqlite3', '-readonly', '-header', '-csv', str(history_file), q],
            timeout_sec=18,
        )
        if raw:
            lines = [ln for ln in raw.splitlines() if ln.strip()]
            if len(lines) <= 1:
                raw = ''
            else:
                prefixed = []
                header = lines[0]
                prefixed.append(f'browser,profile,{header}')
                for ln in lines[1:]:
                    prefixed.append(f'{browser_name},{profile_name},{ln}')
                Path(outpath).write_text('\n'.join(prefixed) + '\n', encoding='utf-8')
                return True, ''

        if not raw:
            # Fallback to Safari Downloads plist if DB access is denied/unavailable.
            plist = Path.home() / 'Library/Safari/Downloads.plist'
            if plist.exists():
                praw, _ = _run_cmd_timeout(['plutil', '-convert', 'json', '-o', '-', str(plist)], timeout_sec=12)
                if praw:
                    try:
                        pobj = json.loads(praw)
                        rows = []
                        if isinstance(pobj, list):
                            for it in pobj:
                                if not isinstance(it, dict):
                                    continue
                                rows.append({
                                    'browser': browser_name,
                                    'profile': profile_name,
                                    'url': it.get('DownloadEntryURL') or it.get('URL') or it.get('DownloadEntryIdentifier') or '',
                                    'title': it.get('DownloadEntryPath') or it.get('DownloadEntryProgressTotalToLoad') or '',
                                    'visit_time': it.get('DownloadEntryDateAddedKey') or it.get('DownloadEntryDateFinishedKey') or '',
                                })
                        if rows:
                            import csv as _csv
                            with open(outpath, 'w', newline='', encoding='utf-8') as f:
                                writer = _csv.DictWriter(f, fieldnames=['browser', 'profile', 'url', 'title', 'visit_time'])
                                writer.writeheader()
                                for r in rows[:500]:
                                    writer.writerow(r)
                            return True, ''
                    except Exception:
                        pass

            if 'authorization denied' in (serr or '').lower():
                if _manual_download_snapshot(outpath)[0]:
                    return True, ''
                return False, 'Safari history DB access denied by macOS privacy controls (grant Full Disk Access to Terminal/Python)'
            if 'timeout after' in (serr or '').lower():
                if _manual_download_snapshot(outpath)[0]:
                    return True, ''
                return False, 'Safari history query timed out (browser may be busy/locked). Close Safari and retry.'
            if _manual_download_snapshot(outpath)[0]:
                return True, ''
            return False, 'No download records found'
        if _manual_download_snapshot(outpath)[0]:
            return True, ''
        return False, serr or 'Unable to read Safari history database (grant Full Disk Access to Terminal/Python and retry)'

    tmp = Path(outpath).with_suffix('.tmp.db')
    try:
        try:
            shutil.copy2(str(history_file), str(tmp))
            db_to_open = tmp
        except Exception:
            db_to_open = history_file

        conn = sqlite3.connect(str(db_to_open))
        try:
            if browser_name.lower() == 'safari' and _table_exists(conn, 'history_visits') and _table_exists(conn, 'history_items'):
                df = pd.read_sql_query(
                    "SELECT datetime(history_visits.visit_time+978307200, 'unixepoch', 'localtime') AS visit_time, "
                    'history_items.url AS url, history_items.title AS title '
                    'FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id '
                    'WHERE lower(history_items.url) LIKE "%.zip" OR lower(history_items.url) LIKE "%.dmg" '
                    'OR lower(history_items.url) LIKE "%.pkg" OR lower(history_items.url) LIKE "%download%" '
                    'OR lower(history_items.title) LIKE "%download%" '
                    'ORDER BY history_visits.visit_time DESC LIMIT 500;',
                    conn,
                )
            if browser_name.lower() in ('chrome', 'chromium', 'edge', 'brave', 'opera', 'vivaldi') and _table_exists(conn, 'downloads'):
                df = pd.read_sql_query('SELECT * FROM downloads LIMIT 500;', conn)
            elif 'df' not in locals():
                source_table = 'moz_places' if 'places.sqlite' in str(history_file).lower() else 'urls'
                df = _fallback_download_rows(conn, source_table)
        finally:
            conn.close()

        if df is None or df.empty:
            if _manual_download_snapshot(outpath)[0]:
                return True, ''
            return False, 'No download records found'

        df.insert(0, 'browser', browser_name)
        df.insert(1, 'profile', profile_name)
        df.to_csv(outpath, index=False)
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        try:
            if tmp and tmp.exists():
                tmp.unlink()
        except Exception:
            pass


def browser_extension_risk_scoring():
    """Score browser extensions/add-ons for basic DFIR risk indicators."""
    data = collect_browser_extensions_inventory()
    if not data:
        console.print('[yellow]No browser extension/add-on rows available to score.[/yellow]')
        return

    risk_terms = {
        'nativeMessaging': 18,
        'webrequest': 15,
        'webrequestblocking': 20,
        'declarativenetrequestwithhostaccess': 16,
        'proxy': 14,
        'tabs': 8,
        'history': 10,
        'cookies': 14,
        'downloads': 8,
        'clipboardwrite': 20,
        'management': 10,
        'browsingdata': 12,
        'debugger': 22,
        'scripting': 10,
        'bookmarks': 6,
        'sessions': 8,
        'storage': 4,
        'identity': 8,
        'alarms': 2,
        'webnavigation': 6,
        'host_permissions': 12,
        '*://*/*': 18,
    }

    def _normalize_value(value):
        if value is None:
            return ''
        if isinstance(value, (list, tuple, set)):
            return ' '.join(str(v) for v in value)
        if isinstance(value, dict):
            return ' '.join(f'{k}:{v}' for k, v in value.items())
        return str(value)

    def _score_row(row):
        text_parts = []
        for key, value in row.items():
            text_parts.append(f'{key}:{_normalize_value(value)}')
        text = ' '.join(text_parts).lower()

        score = 0
        factors = []
        for term, weight in risk_terms.items():
            if term.lower() in text:
                score += weight
                factors.append(term)

        if any(word in text for word in ('vpn', 'password', 'credential', 'cookie', 'token', 'session', 'remote desktop', 'proxy')):
            score += 8
            factors.append('sensitive capability')
        if any(word in text for word in ('allow', 'all urls', 'all_urls', '<all_urls>', 'host_permissions')):
            score += 10
            factors.append('broad host access')
        if any(word in text for word in ('signed by', 'verified publisher', 'mozilla', 'google', 'microsoft')):
            score = max(score - 6, 0)
            factors.append('trusted publisher indicator')

        if score >= 45:
            level = 'Critical'
        elif score >= 30:
            level = 'High'
        elif score >= 15:
            level = 'Medium'
        elif score > 0:
            level = 'Low'
        else:
            level = 'Info'

        name = _normalize_value(row.get('name') or row.get('title') or row.get('extension_name') or row.get('addon_name') or row.get('display_name'))
        version = _normalize_value(row.get('version') or row.get('addon_version') or row.get('manifest_version'))
        browser = _normalize_value(row.get('browser') or row.get('browser_name') or row.get('source_browser') or '')

        return {
            'browser': browser,
            'name': name,
            'version': version,
            'risk_score': min(score, 100),
            'risk_level': level,
            'risk_factors': '; '.join(dict.fromkeys(factors)),
            'raw_summary': text[:1000],
        }

    scored = []
    for row in data:
        if not isinstance(row, dict):
            continue
        scored_row = _score_row(row)
        if not scored_row['browser']:
            scored_row['browser'] = str(row.get('browser', 'unknown'))
        scored.append(scored_row)

    if not scored:
        console.print('[yellow]No browser extension/add-on rows available to score.[/yellow]')
        return

    scored.sort(key=lambda r: r.get('risk_score', 0), reverse=True)
    display_and_export('browser_extension_risk', scored)


def browser_artifacts_menu():
    def _is_macos_tcc_denied(err_text):
        s = (err_text or '').strip().lower()
        return (
            'authorization denied' in s
            or 'operation not permitted' in s
            or 'full disk access' in s
            or 'access denied by macos privacy controls' in s
        )

    def _print_macos_privacy_guidance_once(flag_state):
        if flag_state.get('shown'):
            return
        console.print('[yellow]Safari data access is blocked by macOS privacy controls (TCC).[/yellow]')
        console.print('[dim]Grant Full Disk Access to the app running this script (Terminal/iTerm/VS Code) and its Python host, then restart that app and rerun browser artifacts.[/dim]')
        flag_state['shown'] = True

    while True:
        consoles = detect_browsers()
        macos_privacy_hint = {'shown': False}

        def _print_linux_browser_hints(prefix=''):
            if PLATFORM_RUNTIME.os_key != 'linux':
                return
            install_inventory = _linux_browser_installation_inventory()
            missing = []
            for browser_name, paths in install_inventory.items():
                if browser_name not in consoles and paths:
                    missing.append((browser_name, paths))
            if missing:
                if prefix:
                    console.print(prefix)
                console.print('[dim]Installed browsers with no readable profile data:[/dim]')
                for browser_name, paths in missing:
                    preview = '; '.join(paths[:3])
                    console.print(f'- {browser_name}: installed, but no profile data found yet ({preview})')
            elif not consoles:
                if prefix:
                    console.print(prefix)
                console.print('[yellow]No browser profile data found. Installed browsers may not have created user profiles yet or may be under a different package location.[/yellow]')

        console.print('\nBrowser artifact options:')
        console.print('1. List detected browsers/profiles')
        console.print('2. Dump history to CSV/XLSX')
        console.print('3. List browser extensions/add-ons (all supported browsers)')
        console.print('4. Dump cookies to CSV')
        console.print('5. Score browser extensions/add-ons')
        console.print('6. Dump download history to CSV')
        console.print('7. Back')
        choice = console.input('Choose (1-7): ')
        if choice == '1':
            console.print('Detected browsers:')
            for name, profs in consoles.items():
                console.print(f'- {name}: {len(profs)} profile(s)')
                for p in profs:
                    console.print(f'    {p["name"]}: {p["history"]}')

            _print_linux_browser_hints()
        elif choice == '2':
            if not consoles:
                _print_linux_browser_hints('No browsers detected')
                continue
            for name, profs in consoles.items():
                for p in profs:
                    outdir = Path('outputs')
                    outdir.mkdir(exist_ok=True)
                    fname = outdir / f'{name}_{p["name"]}_history.csv'
                    ok, err = dump_history_to_csv(p.get('history'), profile_dir=p.get('profile_dir'), browser_name=name, outpath=fname)
                    if ok:
                        console.print(f'exported {fname}')
                    else:
                        if PLATFORM_RUNTIME.os_key == 'macos' and name.lower() == 'safari' and _is_macos_tcc_denied(err):
                            _print_macos_privacy_guidance_once(macos_privacy_hint)
                            err = 'Safari history access blocked by macOS privacy controls (no readable fallback rows found)'
                        if PLATFORM_RUNTIME.os_key == 'macos' and name.lower() == 'safari':
                            safari_db = p.get('history')
                            safari_db_exists = bool(safari_db and Path(safari_db).exists())
                            err_l = (err or '').lower()
                            open_failed = (
                                'unable to read safari history database' in err_l
                                or 'authorization denied' in err_l
                                or 'operation not permitted' in err_l
                                or 'permission denied' in err_l
                                or 'database is locked' in err_l
                                or 'access is blocked by macos privacy controls' in err_l
                            )
                            if safari_db_exists and open_failed:
                                console.print('[yellow]Safari History.db exists but could not be opened. Check macOS Privacy & Security -> Full Disk Access and enable it for Python (and Terminal/iTerm/VS Code), then restart and retry.[/yellow]')
                        console.print(f'[yellow]Skipping {name} {p.get("name", "Default")}: {err}[/yellow]')
        elif choice == '3':
            data = collect_browser_extensions_inventory()
            if data:
                display_and_export('browser_extensions_inventory', data)
            else:
                console.print('[yellow]No browser extension/add-on inventory found.[/yellow]')
                _print_linux_browser_hints()
        elif choice == '4':
            browser_cookies()
        elif choice == '5':
            browser_extension_risk_scoring()
        elif choice == '6':
            if not consoles:
                _print_linux_browser_hints('No browsers detected')
                continue
            for name, profs in consoles.items():
                for p in profs:
                    outdir = Path('outputs')
                    outdir.mkdir(exist_ok=True)
                    fname = outdir / f'{name}_{p["name"]}_downloads.csv'
                    # Use history if available, otherwise use profile_dir
                    source_db = p.get('history') or p.get('profile_dir')
                    if not source_db:
                        console.print(f'[yellow]Skipping {name} {p.get("name", "Default")}: no database source[/yellow]')
                        continue
                    ok, err = dump_browser_downloads_to_csv(source_db, name, p['name'], fname)
                    if ok:
                        console.print(f'exported {fname}')
                    else:
                        if PLATFORM_RUNTIME.os_key == 'macos' and name.lower() == 'safari' and _is_macos_tcc_denied(err):
                            _print_macos_privacy_guidance_once(macos_privacy_hint)
                            err = 'Safari download history access blocked by macOS privacy controls (no readable fallback rows found)'
                        console.print(f'[yellow]Skipping {name} {p.get("name", "Default")}: {err}[/yellow]')
        elif choice == '7':
            break
        else:
            break


def file_details():
    """Interactive file metadata analysis."""
    path = console.input('Enter file path: ').strip()
    if not path:
        return
    try:
        import os, hashlib
        if not os.path.exists(path):
            console.print(f'[red]File not found: {path}[/red]')
            return
        stat = os.stat(path)
        with open(path, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        console.print(f'Path: {path}')
        console.print(f'Size: {stat.st_size} bytes')
        console.print(f'Created: {stat.st_ctime}')
        console.print(f'Modified: {stat.st_mtime}')
        console.print(f'Accessed: {stat.st_atime}')
        console.print(f'MD5: {md5}')
        console.print(f'SHA256: {sha256}')
        # Export option
        if console.input('Export to CSV? (y/n): ').lower() == 'y':
            outdir = Path('outputs')
            outdir.mkdir(exist_ok=True)
            fname = outdir / f'file_details_{Path(path).name}.csv'
            import pandas as pd
            df = pd.DataFrame([{
                'path': path, 'size': stat.st_size, 'ctime': stat.st_ctime,
                'mtime': stat.st_mtime, 'atime': stat.st_atime, 'md5': md5, 'sha256': sha256
            }])
            df.to_csv(fname, index=False)
            console.print(f'Exported to {fname}')
    except Exception as e:
        console.print(f'[red]Error: {e}[/red]')


def process_tree():
    """Show process tree for a given PID."""
    pid = console.input('Enter PID: ').strip()
    if not pid.isdigit():
        console.print('[red]Invalid PID[/red]')
        return
    pid = int(pid)

    # Validate PID early with psutil if available.
    try:
        import psutil
        if not psutil.pid_exists(pid):
            console.print(f'[yellow]Wrong PID: process {pid} not found.[/yellow]')
            return
    except Exception:
        pass

    def _build_subtree(proc_map, root_pid):
        def build_tree(p, depth=0):
            if p not in proc_map:
                return []
            name, _ = proc_map[p]
            tree = [f"{'  ' * depth}{p}: {name}"]
            children = [c for c, (_, parent) in proc_map.items() if parent == p]
            for child in sorted(children):
                tree.extend(build_tree(child, depth + 1))
            return tree
        return build_tree(root_pid)

    def _build_parent_chain(proc_map, start_pid):
        chain = []
        current = start_pid
        while current in proc_map:
            name, parent = proc_map[current]
            chain.append((current, name))
            if parent == 0 or parent == current:
                break
            current = parent
        return list(reversed(chain))

    # First try osquery
    data = run_osquery('SELECT pid, name, ppid FROM processes;')
    if data and isinstance(data, list) and data and not (isinstance(data[0], dict) and '_error' in data[0]):
        try:
            proc_map = {int(r['pid']): (r.get('name', ''), int(r.get('ppid', 0))) for r in data}
            # If PID isn't present, report clearly instead of generic failure.
            if pid not in proc_map:
                console.print(f'[yellow]Wrong PID: process {pid} not found.[/yellow]')
                return

            # Print ancestor chain + subtree
            chain = _build_parent_chain(proc_map, pid)
            if chain:
                console.print('Process ancestry:')
                for p, name in chain:
                    console.print(f'  {p}: {name}')
            subtree = _build_subtree(proc_map, pid)
            if subtree:
                console.print('\nProcess subtree:')
                console.print('\n'.join(subtree))
                return
        except Exception:
            pass

    # Fallback: psutil if installed (best full ancestry + recursion)
    try:
        import psutil
        proc = psutil.Process(pid)
        # Full ancestor chain
        ancestors = proc.parents()
        if ancestors:
            console.print('Process ancestry:')
            for anc in reversed(ancestors):
                console.print(f'  {anc.pid}: {anc.name()}')
        console.print(f'  {proc.pid}: {proc.name()}')

        # Full subtree
        children = proc.children(recursive=True)
        if children:
            console.print('\nProcess subtree (descendants):')
            for c in children:
                try:
                    console.print(f'  {c.pid}: {c.name()}')
                except Exception:
                    console.print(f'  {c.pid}: <unknown>')
        return
    except psutil.NoSuchProcess:
        console.print(f'[yellow]Wrong PID: process {pid} not found.[/yellow]')
        return
    except Exception:
        pass

    # Final fallback: wmic
    res = run_command('wmic process get ProcessId,ParentProcessId,Name /FORMAT:CSV', shell=True)
    if res and isinstance(res, list) and res and '_output' in res[0]:
        lines = [l for l in res[0]['_output'].splitlines() if l.strip()]
        proc_map = {}
        if len(lines) > 1:
            headers = [h.strip().lower() for h in lines[0].split(',') if h.strip()]
            for ln in lines[1:]:
                parts = [p.strip() for p in ln.split(',')]
                if len(parts) != len(headers):
                    continue
                row = dict(zip(headers, parts))
                try:
                    pid_val = int(row.get('processid') or 0)
                    ppid_val = int(row.get('parentprocessid') or 0)
                    proc_map[pid_val] = (row.get('name', ''), ppid_val)
                except Exception:
                    continue
        chain = _build_parent_chain(proc_map, pid)
        if chain:
            console.print('Process ancestry:')
            for p, name in chain:
                console.print(f'  {p}: {name}')
        subtree = _build_subtree(proc_map, pid)
        if subtree:
            console.print('\nProcess subtree:')
            console.print('\n'.join(subtree))
            return

    console.print('[red]Unable to build process tree (osquery/psutil/wmic failed).[/red]')


def deleted_files_metadata():
    """Note: osquery doesn't support deleted files directly. Showing recent file changes."""
    console.print('Note: Deleted file metadata requires forensic tools. Showing recent file deletions from event logs.')
    data = run_osquery("SELECT datetime, data FROM windows_eventlog WHERE eventid=4660 AND data LIKE '%DELETE%' ORDER BY datetime DESC LIMIT 50;")
    if data:
        display_and_export('deleted_files_events', data)
    else:
        console.print('No deletion events found or event log access denied.')

    # Also check recycle bin
    console.print('Checking Recycle Bin contents...')
    data2 = run_osquery("SELECT path, size, mtime FROM file WHERE directory LIKE '%$RECYCLE.BIN%' ORDER BY mtime DESC LIMIT 100;")
    if data2:
        display_and_export('recycle_bin_contents', data2)
    else:
        console.print('No items in Recycle Bin or access denied.')


def autoruns_registry():
    """Show registry autorun entries from common Run/RunOnce keys.

    Note: This checks standard Windows autorun locations only.
    Attackers may hide persistence in other registry keys.
    For comprehensive scanning, use custom registry queries or forensic tools.
    """
    keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        # Additional common persistence keys
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        r"HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar",
        r"HKCU\SOFTWARE\Microsoft\Internet Explorer\Toolbar",
    ]
    results = []
    for key in keys:
        console.print(f'Checking {key}...')
        res = run_command(f'reg query "{key}"', shell=True)
        if not res or not isinstance(res, list) or '_output' not in res[0]:
            continue
        out = res[0]['_output']
        # reg query output lines like: <name>    <type>    <data>
        for line in out.splitlines():
            if not line.strip() or line.strip().startswith('HKEY'):
                continue
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 3:
                results.append({'registry_key': key, 'name': parts[0], 'type': parts[1], 'data': parts[2]})
    if results:
        console.print(f'Found {len(results)} autorun entries in standard locations.')
        display_and_export('autoruns_registry', results)
    else:
        console.print('No autoruns found in standard registry locations.')
        console.print('[yellow]Note: This only checks common autorun keys. Attackers may use other locations.[/yellow]')


def wmi_persistence():
    """Collect WMI persistence artifacts (Event Filters / Consumers / Bindings)."""
    def _parse_wmic_list(output):
        items = []
        current = {}
        for line in output.splitlines():
            if not line.strip() and current:
                items.append(current)
                current = {}
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                current[k.strip()] = v.strip()
        if current:
            items.append(current)
        return items

    def _parse_wmic_table(output):
        """Fallback parser for WMIC table output when /format:list is ignored."""
        lines = [l.rstrip() for l in output.splitlines() if l.strip()]
        if len(lines) < 2:
            return []
        headers = re.split(r"\s{2,}", lines[0].strip())
        if not headers:
            return []
        items = []
        for row in lines[1:]:
            cols = re.split(r"\s{2,}", row.strip(), maxsplit=len(headers) - 1)
            if len(cols) != len(headers):
                continue
            items.append(dict(zip(headers, cols)))
        return items

    def _collect_wmi(name, cmd):
        console.print(f'Collecting {name}...')
        res = run_command(cmd, shell=True)
        if not res or not isinstance(res, list) or not res:
            return []
        if '_error' in res[0]:
            return []
        out = res[0].get('_output', '')
        if not out or 'No Instance(s) Available' in out:
            return []
        parsed = _parse_wmic_list(out)
        if parsed:
            return parsed
        # Fallback for systems where WMIC returns table format
        return _parse_wmic_table(out)

    artifacts = []
    # Filters
    filters = _collect_wmi(
        '__EventFilter',
        'wmic /namespace:\\\\root\\subscription path __EventFilter get Name,Query,QueryLanguage /format:list'
    )
    if filters:
        artifacts.append(('__EventFilter', filters))

    # Consumers: query concrete subclasses because __EventConsumer often returns "Invalid query"
    consumers = []
    consumers.extend(_collect_wmi(
        'CommandLineEventConsumer',
        'wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer get Name,CommandLineTemplate,ExecutablePath /format:list'
    ))
    consumers.extend(_collect_wmi(
        'ActiveScriptEventConsumer',
        'wmic /namespace:\\\\root\\subscription path ActiveScriptEventConsumer get Name,ScriptingEngine,ScriptText /format:list'
    ))
    consumers.extend(_collect_wmi(
        'NTEventLogEventConsumer',
        'wmic /namespace:\\\\root\\subscription path NTEventLogEventConsumer get Name,SourceName,EventID /format:list'
    ))
    if consumers:
        artifacts.append(('EventConsumers', consumers))

    # Bindings
    bindings = _collect_wmi(
        '__FilterToConsumerBinding',
        'wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding get Filter,Consumer /format:list'
    )
    if bindings:
        artifacts.append(('__FilterToConsumerBinding', bindings))

    if not artifacts:
        console.print('No WMI persistence artifacts found or wmic failed.')
        return

    # Display & export
    for name, items in artifacts:
        console.print(f'WMI {name} entries:')
        display_and_export(f'wmi_{name.lower()}', items)


def installed_programs_with_hashes():
    """Show installed programs with computed hashes if possible."""
    data = run_osquery("SELECT name, version, install_location FROM programs WHERE install_location != '';")
    if not data:
        console.print('[red]No program data[/red]')
        return
    # Compute hashes for executables
    import os, hashlib
    enriched = []
    for row in data:
        name = row.get('name', 'Unknown')
        version = row.get('version', 'Unknown')
        loc = row.get('install_location', '')
        hash_val = 'N/A'
        if loc and os.path.exists(loc):
            try:
                with open(loc, 'rb') as f:
                    hash_val = hashlib.sha256(f.read()).hexdigest()
            except:
                pass
        enriched.append({'name': name, 'version': version, 'install_location': loc, 'sha256': hash_val})
    display_and_export('installed_programs_hashes', enriched)


def logged_in_users():
    """Show logged in users using Windows session APIs (query user / qwinsta)."""
    def _parse_table(text):
        lines = [l for l in text.splitlines() if l.strip()]
        if not lines or len(lines) < 2:
            return []
        headers = re.split(r"\s{2,}", lines[0].strip())
        rows = []
        for line in lines[1:]:
            parts = re.split(r"\s{2,}", line.strip())
            row = {headers[i]: parts[i] if i < len(parts) else '' for i in range(len(headers))}
            rows.append(row)
        return rows

    console.print('Gathering logged-in users via `query user`...')
    res = run_command('query user', shell=True)
    if res and isinstance(res, list) and res and '_output' in res[0]:
        out = res[0]['_output']
        rows = _parse_table(out)
        if rows:
            display_and_export('logged_in_users', rows)
            return
        else:
            console.print('No entries parsed from query user output. Showing raw output:')
            console.print(out)
            return

    res = run_command('qwinsta', shell=True)
    if res and isinstance(res, list) and res and '_output' in res[0]:
        out = res[0]['_output']
        rows = _parse_table(out)
        if rows:
            display_and_export('logged_in_users', rows)
            return
        console.print('No entries parsed from qwinsta output. Showing raw output:')
        console.print(out)
        return

    console.print('[red]Unable to determine logged-in users (query user/qwinsta failed).[/red]')


def file_modification_events():
    """Show recent file modification events from event logs."""
    console.print('Fetching recent file modification events (may take time)...')
    data = run_osquery("SELECT datetime, provider_name, data FROM windows_eventlog WHERE eventid=4663 ORDER BY datetime DESC LIMIT 50;")
    if data:
        display_and_export('file_mod_events', data)
    else:
        console.print('No file modification events found via osquery, trying manual method...')
        # Manual: use wevtutil to query Security log for 4663 events
        res = run_command('wevtutil qe Security /q:"*[System[(EventID=4663)]]" /c:50 /rd:true /f:text', shell=True)
        if res and '_output' in res[0]:
            console.print('Manual file modification events (last 50):')
            console.print(res[0]['_output'])
            outdir = Path('outputs')
            outdir.mkdir(exist_ok=True)
            fname = outdir / 'file_mod_events_manual.txt'
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(res[0]['_output'])
            console.print(f'Saved to {fname}')
        else:
            console.print('Manual method also failed.')


def dll_hijacking_checks():
    """Check for potential DLL search order hijacking."""
    console.print('Checking for DLLs in current directory (potential hijacking)...')
    data = run_osquery("SELECT path FROM file WHERE directory = '.' AND path LIKE '%.dll';")
    if data:
        console.print('DLLs in current directory:')
        for row in data:
            console.print(f'  {row["path"]}')
    else:
        console.print('No DLLs found in current directory.')

    # Manual: check common hijacking locations
    console.print('Checking common DLL hijacking locations...')
    import os
    paths = os.environ.get('PATH', '').split(';')
    suspicious = []
    for p in paths[:10]:  # limit to first 10
        if os.path.exists(p):
            try:
                dlls = [f for f in os.listdir(p) if f.lower().endswith('.dll')]
                if dlls:
                    suspicious.extend([os.path.join(p, d) for d in dlls[:5]])  # limit
            except:
                pass
    if suspicious:
        console.print('DLLs in PATH directories (potential hijacking):')
        for dll in suspicious:
            console.print(f'  {dll}')
    else:
        console.print('No DLLs found in PATH directories.')


def browser_cookies():
    """Dump browser cookies from local profile databases with fallback support."""
    browsers = detect_browsers()
    if not browsers:
        if PLATFORM_RUNTIME.os_key == 'linux':
            install_inventory = _linux_browser_installation_inventory()
            if install_inventory:
                console.print('[yellow]No readable browser profiles found. Browsers appear installed, but the profile data is not readable or not yet created.[/yellow]')
                for browser_name, paths in install_inventory.items():
                    if paths:
                        console.print(f'- {browser_name}: installed ({"; ".join(paths[:3])})')
                return
        console.print('No supported browsers detected.')
        return

    import csv, sqlite3, shutil, struct
    from datetime import timedelta
    safari_privacy_warned = {'shown': False}

    def _warn_safari_privacy_once():
        if safari_privacy_warned.get('shown'):
            return
        console.print('[yellow]Safari cookie store exists but could not be opened. Check macOS Privacy & Security -> Full Disk Access and enable it for Python (and Terminal/iTerm/VS Code), then restart and retry.[/yellow]')
        safari_privacy_warned['shown'] = True

    def _is_macos_tcc_denied(err_text):
        s = (err_text or '').strip().lower()
        return (
            'authorization denied' in s
            or 'operation not permitted' in s
            or 'full disk access' in s
            or 'access denied by macos privacy controls' in s
            or 'permission denied' in s
        )

    def _find_cookie_db(profile_dir, browser_name):
        """Find cookie database with fallback to alternative locations."""
        profile_dir = Path(profile_dir)
        browser = browser_name.lower()

        def _candidate_paths(*parts):
            return profile_dir.joinpath(*parts)

        if browser in ('chrome', 'chromium', 'edge', 'brave', 'opera', 'vivaldi'):
            # Chromium-based browsers commonly store cookies either directly in the profile
            # or under the newer Network directory.
            candidates = [
                _candidate_paths('Cookies'),
                _candidate_paths('Network', 'Cookies'),
                _candidate_paths('Default', 'Cookies'),
                _candidate_paths('Default', 'Network', 'Cookies'),
                _candidate_paths('cookies.db'),
                _candidate_paths('browser.db'),
            ]
            if browser == 'opera':
                # Opera's profile root is the browser root; its active profile is usually under Default.
                candidates = [
                    _candidate_paths('Default', 'Network', 'Cookies'),
                    _candidate_paths('Default', 'Cookies'),
                    _candidate_paths('Network', 'Cookies'),
                    _candidate_paths('Cookies'),
                    _candidate_paths('cookies.db'),
                    _candidate_paths('browser.db'),
                ]
        elif browser_name.lower() == 'firefox':
            # Firefox cookie locations
            candidates = [
                profile_dir / 'cookies.sqlite',
                profile_dir / 'cookies.db',
                profile_dir / 'webappsstore.sqlite',
            ]
        elif browser == 'safari':
            safari_cookie_roots = [
                Path.home() / 'Library' / 'Cookies',
                Path.home() / 'Library' / 'Containers' / 'com.apple.Safari' / 'Data' / 'Library' / 'Cookies',
                Path.home() / 'Library' / 'Containers' / 'com.apple.SafariTechnologyPreview' / 'Data' / 'Library' / 'Cookies',
            ]
            candidates = []
            for root in safari_cookie_roots:
                candidates.extend([
                    root / 'Cookies.binarycookies',
                    root / 'com.apple.Safari.binarycookies',
                ])
        else:
            candidates = []
        
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    def _dump_sqlite(db_path, query, outpath):
        try:
            # copy to avoid locked file if browser running
            tmp = Path(outpath).with_suffix('.tmp.db')
            try:
                shutil.copy2(str(db_path), str(tmp))
                db_to_open = tmp
            except Exception:
                db_to_open = db_path
            conn = sqlite3.connect(str(db_to_open))
            df = None
            try:
                import pandas as pd
                df = pd.read_sql_query(query, conn)
                df.to_csv(outpath, index=False)
                return True, ''
            finally:
                conn.close()
                try:
                    if tmp and tmp.exists():
                        tmp.unlink()
                except Exception:
                    pass
        except Exception as e:
            return False, str(e)

    def _build_safe_select(conn, table_name, exclude_columns=None):
        exclude_columns = set(exclude_columns or [])
        cur = conn.execute(f'PRAGMA table_info({table_name});')
        columns = [row[1] for row in cur.fetchall() if row and len(row) > 1]
        select_parts = []
        for column in columns:
            if column in exclude_columns:
                continue
            select_parts.append(f'"{column}"')
        if 'encrypted_value' in columns and 'encrypted_value' not in exclude_columns:
            # Keep the value exportable without forcing SQLite/Pandas to decode the raw blob.
            select_parts.append('hex(encrypted_value) AS encrypted_value_hex')
        if not select_parts:
            return f'SELECT * FROM {table_name};'
        return f'SELECT {", ".join(select_parts)} FROM {table_name};'

    def _format_cookie_date(raw_value):
        try:
            seconds = float(raw_value)
            if not seconds:
                return ''
            return (datetime(2001, 1, 1) + timedelta(seconds=seconds)).isoformat(sep=' ', timespec='seconds')
        except Exception:
            return ''

    def _read_cstring(blob, start_index):
        if start_index < 0 or start_index >= len(blob):
            return ''
        end_index = blob.find(b'\x00', start_index)
        if end_index < 0:
            end_index = len(blob)
        return blob[start_index:end_index].decode('utf-8', errors='replace')

    def _parse_safari_binarycookies(cookie_path):
        rows = []
        try:
            data = Path(cookie_path).read_bytes()
        except Exception as e:
            return rows, str(e)

        if not data.startswith(b'cook') or len(data) < 8:
            return rows, 'Not a binarycookies file'

        try:
            page_count = struct.unpack('>I', data[4:8])[0]
            page_sizes = []
            cursor = 8
            for _ in range(page_count):
                if cursor + 4 > len(data):
                    break
                page_sizes.append(struct.unpack('>I', data[cursor:cursor + 4])[0])
                cursor += 4

            for page_index, page_size in enumerate(page_sizes, 1):
                page = data[cursor:cursor + page_size]
                cursor += page_size
                if len(page) < 12:
                    continue
                cookie_count = struct.unpack('>I', page[4:8])[0]
                offsets = []
                offset_cursor = 8
                for _ in range(cookie_count):
                    if offset_cursor + 4 > len(page):
                        break
                    offsets.append(struct.unpack('>I', page[offset_cursor:offset_cursor + 4])[0])
                    offset_cursor += 4

                for cookie_offset in offsets:
                    if cookie_offset + 44 > len(page):
                        continue
                    record = page[cookie_offset:]
                    cookie_size = struct.unpack('>I', record[0:4])[0]
                    cookie_blob = record[:cookie_size] if cookie_size and cookie_size <= len(record) else record
                    if len(cookie_blob) < 44:
                        continue
                    flags = struct.unpack('>I', cookie_blob[4:8])[0]
                    domain_offset = struct.unpack('>I', cookie_blob[8:12])[0]
                    name_offset = struct.unpack('>I', cookie_blob[12:16])[0]
                    path_offset = struct.unpack('>I', cookie_blob[16:20])[0]
                    value_offset = struct.unpack('>I', cookie_blob[20:24])[0]
                    comment_offset = struct.unpack('>I', cookie_blob[24:28])[0]
                    creation_time = struct.unpack('>d', cookie_blob[28:36])[0]
                    expiry_time = struct.unpack('>d', cookie_blob[36:44])[0]
                    base_offset = 44
                    rows.append({
                        'domain': _read_cstring(cookie_blob, base_offset + domain_offset),
                        'name': _read_cstring(cookie_blob, base_offset + name_offset),
                        'path': _read_cstring(cookie_blob, base_offset + path_offset),
                        'value': _read_cstring(cookie_blob, base_offset + value_offset),
                        'comment': _read_cstring(cookie_blob, base_offset + comment_offset),
                        'creation_time': _format_cookie_date(creation_time),
                        'expiry_time': _format_cookie_date(expiry_time),
                        'flags': flags,
                        'page': page_index,
                        'source': str(cookie_path),
                    })
        except Exception as e:
            return rows, str(e)
        return rows, ''

    for name, profs in browsers.items():
        for p in profs:
            profile_dir = Path(p.get('profile_dir')) if p.get('profile_dir') else (Path(p['history']).parent if p.get('history') else None)
            if not profile_dir:
                console.print(f'Skipping {name} profile {p.get("name", "Default")}: profile directory not found')
                continue
            
            if name.lower() in ('chrome', 'chromium', 'edge', 'brave', 'opera', 'vivaldi'):
                query = None
            elif name.lower() == 'firefox':
                query = None
            elif name.lower() == 'safari':
                query = None
            else:
                console.print(f'Cookies not supported for {name}')
                continue

            cookie_db = _find_cookie_db(profile_dir, name)
            if not cookie_db:
                console.print(f'[yellow]Cookie DB not found for {name} profile {p["name"]}: no standard cookie database located[/yellow]')
                continue

            if name.lower() == 'safari' and str(cookie_db).lower().endswith('binarycookies'):
                rows, err = _parse_safari_binarycookies(cookie_db)
                if not rows:
                    if PLATFORM_RUNTIME.os_key == 'macos' and Path(cookie_db).exists() and _is_macos_tcc_denied(err):
                        _warn_safari_privacy_once()
                    console.print(f'[red]Failed to parse Safari cookies for {p["name"]}: {err or "no cookie rows found"}[/red]')
                    continue
                outdir = Path('outputs')
                outdir.mkdir(exist_ok=True)
                fname = outdir / f'{name}_{p["name"]}_cookies.csv'
                try:
                    with open(fname, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                        writer.writeheader()
                        writer.writerows(rows)
                    console.print(f'[green]Exported Safari cookies to {fname}[/green]')
                except Exception as e:
                    console.print(f'[red]Failed to write Safari cookies for {p["name"]}: {e}[/red]')
                continue

            try:
                if name.lower() in ('chrome', 'chromium', 'edge', 'brave', 'opera', 'vivaldi'):
                    with sqlite3.connect(str(cookie_db)) as conn:
                        query = _build_safe_select(conn, 'cookies', exclude_columns={'encrypted_value'})
                else:
                    with sqlite3.connect(str(cookie_db)) as conn:
                        query = _build_safe_select(conn, 'moz_cookies')
            except Exception as e:
                if PLATFORM_RUNTIME.os_key == 'macos' and name.lower() == 'safari' and Path(cookie_db).exists() and _is_macos_tcc_denied(str(e)):
                    _warn_safari_privacy_once()
                console.print(f'[red]Failed to inspect cookie schema for {name} {p["name"]}: {e}[/red]')
                continue

            outdir = Path('outputs')
            outdir.mkdir(exist_ok=True)
            fname = outdir / f'{name}_{p["name"]}_cookies.csv'
            ok, err = _dump_sqlite(cookie_db, query, fname)
            if ok:
                console.print(f'[green]Exported cookies to {fname}[/green]')
            else:
                if PLATFORM_RUNTIME.os_key == 'macos' and name.lower() == 'safari' and Path(cookie_db).exists() and _is_macos_tcc_denied(err):
                    _warn_safari_privacy_once()
                console.print(f'[red]Failed to dump cookies for {name} {p["name"]}: {err}[/red]')


def process_injection_detection():
    """Detect potential process injection by checking loaded DLLs."""
    data = run_osquery("SELECT pid, path FROM process_memory_map WHERE path LIKE '%.dll' AND path NOT LIKE '%\\\\Windows\\\\System32%' ORDER BY pid;")
    if data:
        display_and_export('process_injection_suspects', data)
    else:
        console.print('No suspicious DLL loads detected.')


def detect_base64_commands():
    """Scan PowerShell history for base64 encoded commands."""
    import base64, re
    data = run_osquery("SELECT path FROM file WHERE path LIKE '%ConsoleHost_history.txt';")
    if not data:
        console.print('No PowerShell history found.')
        return
    for row in data:
        path = row[0]
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                for line in lines:
                    if re.search(r'[A-Za-z0-9+/=]{20,}', line):  # potential base64
                        try:
                            decoded = base64.b64decode(line).decode('utf-8')
                            if 'powershell' in decoded.lower() or 'cmd' in decoded.lower():
                                console.print(f'Suspicious encoded command: {line[:50]}... -> {decoded[:50]}...')
                        except:
                            pass
    console.print('Scan complete.')


def detect_encoded_powershell():
    """Detect encoded PowerShell commands in history."""
    detect_base64_commands()  # reuse


def get_clipboard_logs():
    """Retrieve clipboard contents using PowerShell."""
    try:
        # Force text mode to avoid object/binary clipboard formats.
        res = run_command('powershell -command "Get-Clipboard -Format Text -Raw"', shell=True)
        if res and '_error' in res[0]:
            console.print(f'[red]Failed: {res[0]["_error"]}[/red]')
        else:
            content = res[0].get('_output', '').strip()
            if not content:
                console.print('[yellow]Clipboard is empty or does not contain plain text.[/yellow]')
                return
            console.print('Clipboard content:')
            console.print(content)
            # Ask to save to file
            save = console.input('Save to file? (y/n): ').strip().lower()
            if save == 'y':
                outdir = Path('outputs')
                outdir.mkdir(exist_ok=True)
                fname = outdir / 'clipboard_log.txt'
                fname.write_text(content)
                console.print(f'Saved to {fname}')
            else:
                console.print('Not saved.')
    except Exception as e:
        console.print(f'[red]Error: {e}[/red]')


def yara_ioc_scan():
    """Scan files with YARA rules (requires yara-python or yara.exe)."""
    path = console.input('Directory to scan: ').strip()
    rules_file = console.input('YARA rules file path: ').strip()
    if not os.path.exists(path) or not os.path.exists(rules_file):
        console.print('[red]Path or rules file not found[/red]')
        return
    try:
        import yara
        rules = yara.compile(filepath=rules_file)
        matches = []
        for root, dirs, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read(1024*1024)  # first 1MB
                        m = rules.match(data=data)
                        if m:
                            matches.append((filepath, m))
                except:
                    pass
        if matches:
            console.print('YARA matches:')
            for fp, m in matches:
                console.print(f'{fp}: {m}')
        else:
            console.print('No matches found.')
    except ImportError:
        console.print('[red]yara-python not installed. Install with pip install yara-python[/red]')
    except Exception as e:
        console.print(f'[red]Error: {e}[/red]')


def yara_ioc_menu():
    """YARA-based IOC finder menu."""
    while True:
        console.print('\nYARA IOC Finder:')
        console.print('1. Ransomware IOCs')
        console.print('2. C2 (Command & Control) IOCs')
        console.print('3. Credential Access IOCs')
        console.print('4. Malware Persistence IOCs')
        console.print('5. Custom YARA Scan')
        console.print('6. Back')
        choice = console.input('Choose (1-6): ')
        if choice == '1':
            # Ransomware rules: advanced patterns for notes, extensions, encryptors
            rules_str = """
rule ransomware_ransom_note {
    meta:
        description = "Detects common ransomware ransom note patterns"
    strings:
        $note1 = "Your files have been encrypted" nocase
        $note2 = "pay bitcoin" nocase
        $note3 = "decrypt your files" nocase
        $note4 = "ransomware" nocase
        $ext1 = ".locky" nocase
        $ext2 = ".wannacry" nocase
        $ext3 = ".crypt" nocase
    condition:
        (any of ($note*)) or (any of ($ext*))
}

rule ransomware_encryptor {
    meta:
        description = "Detects encryption algorithms and ransomware behaviors"
    strings:
        $aes = "AES_encrypt" nocase
        $rsa = "RSA_public_encrypt" nocase
        $xor = "XOR_encrypt" nocase
        $file_enum = "FindFirstFile" nocase
        $file_write = "WriteFile" nocase
        $ransom_ext = /[a-zA-Z0-9]{4,}\.(encrypted|locked|crypted|crypt)/ nocase
    condition:
        ($aes or $rsa or $xor) and ($file_enum or $file_write) or $ransom_ext
}

rule ransomware_file_modification {
    meta:
        description = "Detects mass file encryption patterns"
    strings:
        $bulk_encrypt = "encrypting files" nocase
        $extension_change = "change file extension" nocase
        $readme = "README.txt" nocase
    condition:
        any of them
}
"""
            yara_scan_with_rules(rules_str, "Ransomware IOCs")
        elif choice == '2':
            # C2: advanced beacon patterns, C2 communications
            rules_str = """
rule c2_http_beacon {
    meta:
        description = "Detects HTTP-based C2 beacons"
    strings:
        $http_get = "GET /" nocase
        $http_post = "POST /" nocase
        $user_agent = "User-Agent:" nocase
        $host = "Host:" nocase
        $suspicious_domain = /[a-zA-Z0-9-]+\.(onion|xyz|top|club|ru|cn)/ nocase
        $ip_pattern = /\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b/
        $port = /:\\d{2,5}/
    condition:
        ($http_get or $http_post) and ($user_agent or $host) and ($suspicious_domain or ($ip_pattern and $port))
}

rule c2_dns_tunneling {
    meta:
        description = "Detects DNS tunneling for C2"
    strings:
        $dns_query = "DNS" nocase
        $base64_dns = /[a-zA-Z0-9+/=]{10,}/ nocase
        $long_domain = /[a-zA-Z0-9-]{50,}\\.[a-z]{2,}/ nocase
    condition:
        $dns_query and ($base64_dns or $long_domain)
}

rule c2_websocket {
    meta:
        description = "Detects WebSocket C2 communications"
    strings:
        $ws_upgrade = "Upgrade: websocket" nocase
        $ws_key = "Sec-WebSocket-Key:" nocase
        $ws_accept = "Sec-WebSocket-Accept:" nocase
    condition:
        any of them
}
"""
            yara_scan_with_rules(rules_str, "C2 IOCs")
        elif choice == '3':
            # Credential access: advanced patterns for dumping tools
            rules_str = """
rule mimikatz_detection {
    meta:
        description = "Detects Mimikatz tool usage"
    strings:
        $mimi1 = "mimikatz" nocase
        $mimi2 = "sekurlsa" nocase
        $mimi3 = "logonpasswords" nocase
        $mimi4 = "kerberos" nocase
        $mimi5 = "lsadump" nocase
        $mimi6 = "privilege::debug" nocase
    condition:
        any of them
}

rule lsass_dump {
    meta:
        description = "Detects LSASS memory dumping"
    strings:
        $lsass1 = "lsass.exe" nocase
        $lsass2 = "MiniDumpWriteDump" nocase
        $lsass3 = "procdump" nocase
        $lsass4 = "rundll32.exe" nocase
        $lsass5 = "comsvcs.dll" nocase
        $lsass6 = "MiniDump" nocase
    condition:
        $lsass1 and (any of ($lsass2, $lsass3, $lsass4, $lsass5, $lsass6))
}

rule credential_theft {
    meta:
        description = "Detects credential theft patterns"
    strings:
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $cred3 = "hashdump" nocase
        $cred4 = "samdump" nocase
        $cred5 = "ntds.dit" nocase
        $cred6 = "SYSTEM" nocase
        $cred7 = "SAM" nocase
    condition:
        ($cred1 or $cred2) and any of ($cred3, $cred4, $cred5, $cred6, $cred7)
}
"""
            yara_scan_with_rules(rules_str, "Credential Access IOCs")
        elif choice == '4':
            # Persistence: advanced registry, startup, WMI
            rules_str = """
rule registry_persistence {
    meta:
        description = "Detects registry-based persistence"
    strings:
        $run = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $runonce = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce" nocase
        $image_file_exec = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options" nocase
        $shell_ext = "SOFTWARE\\\\Classes\\\\*\\\\shellex" nocase
        $appinit = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs" nocase
    condition:
        any of them
}

rule startup_persistence {
    meta:
        description = "Detects startup folder persistence"
    strings:
        $startup = "Start Menu\\\\Programs\\\\Startup" nocase
        $allusers_startup = "All Users\\\\Start Menu\\\\Programs\\\\Startup" nocase
    condition:
        any of them
}

rule wmi_persistence {
    meta:
        description = "Detects WMI event subscription persistence"
    strings:
        $wmi1 = "ActiveScriptEventConsumer" nocase
        $wmi2 = "__EventFilter" nocase
        $wmi3 = "__FilterToConsumerBinding" nocase
        $wmi4 = "CommandLineEventConsumer" nocase
    condition:
        any of them
}

rule scheduled_task_persistence {
    meta:
        description = "Detects scheduled task persistence"
    strings:
        $task1 = "schtasks" nocase
        $task2 = "Create" nocase
        $task3 = "/sc" nocase
        $task4 = "/tn" nocase
        $task5 = "/tr" nocase
    condition:
        $task1 and ($task2 or $task3 or $task4 or $task5)
}
"""
            yara_scan_with_rules(rules_str, "Malware Persistence IOCs")
        elif choice == '5':
            yara_ioc_scan()  # custom
        else:
            break


def yara_scan_with_rules(rules_str, title):
    """Scan with embedded YARA rules."""
    path = console.input('Directory to scan for file/script IOC patterns (e.g., C:\\ or C:\\Users\\IEUser\\Downloads). Leave blank to skip file scan: ').strip()
    if not path:
        console.print('[yellow]Skipped file-based YARA scan.[/yellow]')
        return
    if not os.path.exists(path):
        console.print('[red]Path not found.[/red]')
        console.print('[yellow]Use a valid local directory path, for example: C:\\Users\\IEUser\\Downloads[/yellow]')
        return
    console.print(f'Scanning {path} with {title} rules... This may take time.')
    max_files = 5000  # Limit to prevent excessive scanning
    try:
        import yara
        rules = yara.compile(source=rules_str)
        matches = []
        total_files = 0
        for root, dirs, files in os.walk(path):
            for file in files:
                if total_files >= max_files:
                    console.print(f'Stopped at {max_files} files to prevent excessive scanning. Use a more specific directory.')
                    break
                filepath = os.path.join(root, file)
                total_files += 1
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()  # Read whole file for better detection
                        m = rules.match(data=data)
                        if m:
                            matches.append((filepath, m))
                except:
                    pass
            if total_files >= max_files:
                break
        console.print(f'Scanned {total_files} files. {title} results:')
        if matches:
            for fp, m in matches:
                rules_matched = ', '.join([str(rule) for rule in m])
                console.print(f'File: {fp}')
                console.print(f'  Matched rules: {rules_matched}')
                console.print()
            # Export
            outdir = Path('outputs')
            outdir.mkdir(exist_ok=True)
            fname = outdir / f'{title.replace(" ", "_")}_matches.txt'
            with open(fname, 'w') as f:
                for fp, m in matches:
                    rules_matched = ', '.join([str(rule) for rule in m])
                    f.write(f'File: {fp}\n  Matched rules: {rules_matched}\n\n')
            console.print(f'Results exported to {fname}')
        else:
            console.print('No matches found.')
    except ImportError:
        console.print('[red]yara-python not installed[/red]')
    except Exception as e:
        console.print(f'[red]Error: {e}[/red]')


def system_info_detailed():
    """Show Windows systeminfo output and optionally save it."""
    console.print('Fetching Windows systeminfo output...')
    res = run_command('systeminfo', shell=True)
    if res and isinstance(res, list) and res and '_output' in res[0]:
        out = res[0]['_output']
        console.print(out)

        save = console.input('Save systeminfo output to outputs/systeminfo_output.txt? (y/N): ').strip().lower()
        if save == 'y':
            outdir = Path('outputs')
            outdir.mkdir(exist_ok=True)
            fname = outdir / 'systeminfo_output.txt'
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(out)
            console.print(f'Systeminfo output saved to {fname}')
        else:
            console.print('Skipping save.')
    else:
        console.print('systeminfo command failed.')


def detect_suspicious_scheduled_tasks():
    """Check for suspicious scheduled tasks."""
    data = run_osquery("SELECT name, action FROM scheduled_tasks WHERE action LIKE '%powershell%' OR action LIKE '%cmd%' OR action LIKE '%wget%' OR action LIKE '%curl%';")
    if data:
        display_and_export('suspicious_tasks', data)
    else:
        console.print('No suspicious tasks found.')


def detect_known_malicious_files():
    """Search for known malicious file names."""
    malicious_names = ['ransomware.exe', 'trojan.dll', 'keylogger.exe']  # example
    query = " OR ".join([f"path LIKE '%{name}%'" for name in malicious_names])
    data = run_osquery(f"SELECT path FROM file WHERE {query};")
    if data:
        console.print('Known malicious files found:')
        for row in data:
            console.print(row[0])
    else:
        console.print('No known malicious files detected.')


def detect_behavior_anomalies():
    """Detect anomalies like high CPU processes."""
    data = run_osquery("SELECT pid, name, cpu_percent FROM processes WHERE cpu_percent > 80 ORDER BY cpu_percent DESC LIMIT 10;")
    if data:
        display_and_export('high_cpu_processes', data)
    else:
        console.print('No high CPU processes.')


def detect_encryptor_activity():
    """Look for encryption-related logs."""
    data = run_osquery("SELECT datetime, message FROM windows_eventlog WHERE message LIKE '%encrypt%' ORDER BY datetime DESC LIMIT 20;")
    if data:
        display_and_export('encryption_logs', data)
    else:
        console.print('No encryption activity in logs.')


def is_admin():
    """Check if running as admin."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def remove_persistence():
    """Remove persistence mechanisms with looping menu."""
    def confirm_action(message):
        return console.input(f'{message} (y/n): ').strip().lower() == 'y'
    
    while True:
        console.print('\nRemove persistence:')
        console.print('1. Scheduled task  2. Registry autorun  3. Startup item  4. WMI  5. Service  6. Back')
        sub = console.input('Choose (1-6): ').strip()
        if sub == '1':
            task = console.input('Task name: ').strip()
            if task:
                if confirm_action(f'Are you sure you want to delete scheduled task "{task}"?'):
                    res = run_command(f'schtasks /delete /tn "{task}" /f', shell=True)
                    console.print('Task deleted' if not res or '_error' not in res[0] else f'Error: {res[0]["_error"]}')
                else:
                    console.print('Cancelled.')
            else:
                console.print('[yellow]No task name entered.[/yellow]')
        elif sub == '2':
            key = console.input('Registry value name (e.g., TestStartupSafe): ').strip()
            if not key:
                console.print('[yellow]No value name entered.[/yellow]')
            else:
                if confirm_action(f'Are you sure you want to delete registry value "{key}" from all common autorun keys?'):
                    # Delete the value from common autorun and persistence keys
                    run_keys = [
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                        # Additional common persistence keys
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                        r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                        r"HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar",
                        r"HKCU\SOFTWARE\Microsoft\Internet Explorer\Toolbar",
                    ]
                    deleted = False
                    for rk in run_keys:
                        res = run_command(f'reg delete "{rk}" /v "{key}" /f', shell=True)
                        if not res or '_error' not in res[0]:
                            console.print(f'Deleted value "{key}" from {rk}')
                            deleted = True
                    if not deleted:
                        console.print('[yellow]Value not found in autorun registry keys.[/yellow]')
                else:
                    console.print('Cancelled.')
        elif sub == '3':
            item = console.input('Startup item name to remove (leave blank to list): ').strip()
            if not item:
                # Use artifact key that maps to startup_items SQL in queries.py
                data = run_osquery('autoruns_startupfolders')
                display_and_export('startup_items', data)
            else:
                if confirm_action(f'Are you sure you want to remove startup item "{item}" (registry and files)?'):
                    # remove from startup_items / startup folder (try both)
                    registry_removed = False
                    run_keys = [
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                        # Additional common persistence keys
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                        r"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                        r"HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar",
                        r"HKCU\SOFTWARE\Microsoft\Internet Explorer\Toolbar",
                    ]
                    for rk in run_keys:
                        res = run_command(f'reg delete "{rk}" /v "{item}" /f', shell=True)
                        if not res or '_error' not in res[0]:
                            console.print(f'Deleted {item} from {rk}')
                            registry_removed = True
                    if not registry_removed:
                        console.print('[yellow]No registry autorun value removed for that name.[/yellow]')

                    # okay to remove from startup folders too
                    startup_paths = [
                        os.path.join(os.environ.get('ALLUSERSPROFILE', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                        os.path.join(os.environ.get('APPDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                    ]
                    for path in startup_paths:
                        if os.path.isdir(path):
                            for filename in os.listdir(path):
                                if item.lower() in filename.lower():
                                    target = os.path.join(path, filename)
                                    if confirm_action(f'Are you sure you want to remove startup file "{target}"?'):
                                        try:
                                            os.remove(target)
                                            console.print(f'Removed startup file: {target}')
                                        except Exception as e:
                                            console.print(f'[red]Failed remove {target}: {e}[/red]')
                                    else:
                                        console.print(f'Skipped {target}')
                else:
                    console.print('Cancelled.')
        elif sub == '4':
            console.print('\n[cyan]WMI Deletion Options:[/cyan]')
            console.print('1. Delete __EventFilter by name')
            console.print('2. Delete CommandLineEventConsumer by name')
            console.print('3. Delete __FilterToConsumerBinding')
            console.print('4. Back')
            wmi_choice = console.input('Choose (1-4): ').strip()

            # Most WMI delete operations require elevated privileges.
            if wmi_choice in ('1', '2', '3') and not is_admin():
                console.print('[red]WMI deletion requires Administrator privileges.[/red]')
                console.print('[yellow]Run ParthaSarathi as Administrator and try again.[/yellow]')
                continue
            
            if wmi_choice == '1':
                filter_name = console.input('Enter filter name (e.g., TestFilter): ').strip()
                if filter_name:
                    if confirm_action(f'Are you sure you want to delete WMI filter "{filter_name}"?'):
                        cmd = f'wmic /namespace:\\\\root\\subscription path __EventFilter where Name="{filter_name}" delete'
                        res = run_command(cmd, shell=True)
                        if res and isinstance(res, list) and '_error' in res[0]:
                            console.print(f'[red]Error: {res[0]["_error"]}[/red]')
                        else:
                            out = res[0].get('_output', '') if res and isinstance(res, list) else ''
                            low = out.lower()
                            if 'no instance' in low:
                                console.print(f'[yellow]Filter "{filter_name}" not found.[/yellow]')
                            elif 'access denied' in low:
                                console.print('[red]Access denied. Run as Administrator.[/red]')
                            else:
                                console.print(f'[green]WMI filter "{filter_name}" deleted.[/green]')
                    else:
                        console.print('Cancelled.')
                else:
                    console.print('[yellow]No filter name provided.[/yellow]')
            elif wmi_choice == '2':
                consumer_name = console.input('Enter consumer name (e.g., TestConsumer): ').strip()
                if consumer_name:
                    if confirm_action(f'Are you sure you want to delete WMI consumer "{consumer_name}"?'):
                        cmd = f'wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer where Name="{consumer_name}" delete'
                        res = run_command(cmd, shell=True)
                        if res and isinstance(res, list) and '_error' in res[0]:
                            console.print(f'[red]Error: {res[0]["_error"]}[/red]')
                        else:
                            out = res[0].get('_output', '') if res and isinstance(res, list) else ''
                            low = out.lower()
                            if 'no instance' in low:
                                console.print(f'[yellow]Consumer "{consumer_name}" not found.[/yellow]')
                            elif 'access denied' in low:
                                console.print('[red]Access denied. Run as Administrator.[/red]')
                            else:
                                console.print(f'[green]WMI consumer "{consumer_name}" deleted.[/green]')
                    else:
                        console.print('Cancelled.')
                else:
                    console.print('[yellow]No consumer name provided.[/yellow]')
            elif wmi_choice == '3':
                console.print('\n[cyan]Current WMI Bindings:[/cyan]')
                # Use PowerShell directly to list and delete bindings more reliably
                ps_list_cmd = 'powershell -Command "Get-WmiObject -Namespace \'root\\subscription\' -Class __FilterToConsumerBinding | Select-Object @{Name=\'Filter\';Expression={$_.Filter}}, @{Name=\'Consumer\';Expression={$_.Consumer}} | Format-Table -AutoSize"'
                res = run_command(ps_list_cmd, shell=True)
                
                if res and isinstance(res, list) and '_output' in res[0]:
                    output = res[0]['_output']
                    console.print(output)
                    
                    console.print('\n[yellow]To delete bindings by consumer name, use option below:[/yellow]')
                    console.print('1. Delete binding by consumer name')
                    console.print('2. Back')
                    sub_choice = console.input('Choose (1-2): ').strip()
                    
                    if sub_choice == '1':
                        consumer_name = console.input('Enter consumer name to remove binding (e.g., TestConsumer): ').strip()
                        if consumer_name:
                            if confirm_action(f'Are you sure you want to delete binding for consumer "{consumer_name}"?'):
                                # Use PowerShell to delete the binding by consumer name
                                ps_delete_cmd = f'powershell -Command "Get-WmiObject -Namespace \'root\\subscription\' -Class __FilterToConsumerBinding | Where-Object {{$_.Consumer -like \'*Name=\\\"{consumer_name}\\\"*\'}} | Remove-WmiObject -Confirm:$false"'
                                res = run_command(ps_delete_cmd, shell=True)
                                
                                if res and isinstance(res, list) and '_error' in res[0]:
                                    console.print(f'[red]Error: {res[0].get("_error", "Unknown error")}[/red]')
                                    console.print('[yellow]Hint: This operation requires running as Administrator.[/yellow]')
                                else:
                                    console.print(f'[green]Binding for consumer "{consumer_name}" deleted.[/green]')
                        else:
                            console.print('[yellow]No consumer name provided.[/yellow]')
                else:
                    console.print('[red]Could not list bindings.[/red]')
                    console.print('[cyan]Manual deletion command:[/cyan]')
                    console.print('powershell -Command "Get-WmiObject -Namespace \'root\\subscription\' -Class __FilterToConsumerBinding | Remove-WmiObject"')
            elif wmi_choice == '4':
                pass  # Go back to main menu
            else:
                console.print('[yellow]Invalid choice.[/yellow]')
        elif sub == '5':
            svc = console.input('Service name: ').strip()
            if svc:
                if confirm_action(f'Are you sure you want to delete service "{svc}"?'):
                    res = run_command(f'sc delete "{svc}"', shell=True)
                    console.print('Service deleted' if not res or '_error' not in res[0] else f'Error: {res[0]["_error"]}')
                else:
                    console.print('Cancelled.')
            else:
                console.print('[yellow]No service name entered.[/yellow]')
        elif sub == '6':
            break
        else:
            console.print('[yellow]Invalid choice.[/yellow]')


def check_data_exfiltration():
    """Check for potential data exfiltration indicators."""
    console.print('Checking for data exfiltration indicators...')
    
    # Method 1: Check for outbound connections on suspicious ports
    console.print('\n[cyan]Checking outbound network connections...[/cyan]')
    try:
        # Use netstat to get connections
        res = run_command('netstat -ano', shell=True)
        if res and isinstance(res, list) and '_output' in res[0]:
            out = res[0]['_output']
            suspicious_ports = [80, 443, 21, 22, 25, 53, 135, 139, 445, 3389, 5985]
            lines = out.splitlines()
            found_suspicious = []
            for line in lines:
                if 'ESTABLISHED' in line or 'ESTABLISHED' in line:
                    for port in suspicious_ports:
                        if f':{port}' in line:
                            found_suspicious.append(line.strip())
            
            if found_suspicious:
                console.print(f'[yellow]Found {len(found_suspicious)} outbound connections on suspicious ports:[/yellow]')
                for conn in found_suspicious[:10]:
                    console.print(f'  {conn}')
                if len(found_suspicious) > 10:
                    console.print(f'  ... and {len(found_suspicious) - 10} more')
            else:
                console.print('[green]No suspicious outbound connections found.[/green]')
    except Exception as e:
        console.print(f'[yellow]Could not check connections via netstat: {e}[/yellow]')
    
    # Method 2: Check system event logs for network/file activity
    console.print('\n[cyan]Checking security event logs...[/cyan]')
    try:
        # Query event log with required WHERE clause
        data = run_osquery("SELECT datetime, eventid, data FROM windows_eventlog WHERE eventid=5156 LIMIT 20;")
        if data and isinstance(data, list) and len(data) > 0 and '_error' not in data[0]:
            console.print(f'[yellow]Found {len(data)} network-related security events (EventID 5156):[/yellow]')
            for row in data[:5]:
                if isinstance(row, dict):
                    console.print(f"  {row.get('datetime', 'N/A')} - {row.get('data', '')[:80]}")
        else:
            console.print('[green]No recent network audit events found.[/green]')
    except Exception as e:
        console.print(f'[yellow]Could not query event logs: {e}[/yellow]')
    
    # Method 3: List all listening processes (potential CnC callbacks)
    console.print('\n[cyan]Checking listening processes...[/cyan]')
    try:
        res = run_command('netstat -ano | findstr LISTENING', shell=True)
        if res and isinstance(res, list) and '_output' in res[0]:
            out = res[0]['_output']
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if lines:
                console.print(f'[yellow]Found {len(lines)} listening ports:[/yellow]')
                for line in lines[:10]:
                    console.print(f'  {line}')
                if len(lines) > 10:
                    console.print(f'  ... and {len(lines) - 10} more')
            else:
                console.print('[green]No suspicious listeners detected.[/green]')
    except Exception as e:
        console.print(f'[yellow]Could not check listening ports: {e}[/yellow]')
    
    console.print('\n[cyan]Tip: For detailed network forensics, use YARA IOC finder for file-based IOCs or check endpoint detection tools.[/cyan]')


def recycle_bin_files():
    """List files in Windows Recycle Bin ($Recycle.Bin)."""
    import os
    import time
    from datetime import datetime
    
    console.print('Scanning Recycle Bin for deleted files...')
    recycle_bin_path = os.path.expandvars(r'%systemdrive%\$Recycle.Bin')
    files_data = []
    
    if not os.path.exists(recycle_bin_path):
        console.print('[yellow]Recycle Bin not found or inaccessible.[/yellow]')
        return
    
    try:
        for user_folder in os.listdir(recycle_bin_path):
            user_path = os.path.join(recycle_bin_path, user_folder)
            if not os.path.isdir(user_path):
                continue
            
            # Iterate through files in user's recycle bin folder
            for filename in os.listdir(user_path):
                filepath = os.path.join(user_path, filename)
                if not os.path.isfile(filepath):
                    continue
                
                try:
                    stat = os.stat(filepath)
                    size = stat.st_size
                    # The deletion time is when the file was moved to recycle bin (creation time on NTFS)
                    deletion_time = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    files_data.append({
                        'user_sid': user_folder,
                        'filename': filename,
                        'size_bytes': size,
                        'deleted_timestamp': deletion_time,
                        'full_path': filepath
                    })
                except Exception as e:
                    console.print(f'[yellow]Could not access {filepath}: {e}[/yellow]')
        
        if files_data:
            console.print(f'\n[green]Found {len(files_data)} files in Recycle Bin[/green]')
            display_and_export('recycle_bin_files', files_data)
        else:
            console.print('[green]Recycle Bin is empty.[/green]')
    
    except PermissionError:
        console.print('[red]Access denied: Requires admin privileges to read Recycle Bin.[/red]')
    except Exception as e:
        console.print(f'[red]Error scanning Recycle Bin: {e}[/red]')


def hosts_file_dns_info():
    """Show current DNS cache information from the live system."""
    console.print('Collecting current DNS cache entries...')
    res = run_command('ipconfig /displaydns', shell=True)
    if not res or not isinstance(res, list) or '_output' not in res[0]:
        err = res[0].get('_error', 'Unknown error') if res and isinstance(res, list) else 'Unknown error'
        console.print(f'[red]Failed to collect DNS cache info: {err}[/red]')
        return

    output = res[0]['_output']
    lines = output.splitlines()
    entries = []
    current = {}

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if set(stripped) == {'-'}:
            if current:
                entries.append(current)
                current = {}
            continue

        if ':' in line:
            k, v = line.split(':', 1)
            key = re.sub(r'\s+\.\s*', ' ', k).strip().lower().replace(' ', '_')
            current[key] = v.strip()

    if current:
        entries.append(current)

    # Fallback to raw output if parsing returns nothing useful
    if not entries:
        entries = [{'dns_cache_output': output[:5000]}]

    display_and_export('current_dns_cache_info', entries)


def network_exposure_windows():
    """Collect Windows network exposure snapshot for MDR triage."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"$riskPorts=@(21,22,23,53,80,88,135,137,138,139,389,443,445,636,1433,1521,3306,3389,5432,5985,5986,8080,8443);"
        "$listeners=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
        "| ForEach-Object {"
        "$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
        "[PSCustomObject]@{"
        "LocalAddress=$_.LocalAddress;"
        "LocalPort=$_.LocalPort;"
        "OwningProcess=$_.OwningProcess;"
        "ProcessName=if($p){$p.ProcessName}else{'Unknown'};"
        "RiskHint=if($riskPorts -contains [int]$_.LocalPort){'Commonly targeted exposed port'}else{''}"
        "}"
        "};"
        "$fw=Get-NetFirewallProfile -ErrorAction SilentlyContinue "
        "| Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction;"
        "$svc=Get-Service -Name TermService,WinRM,LanmanServer,RemoteRegistry -ErrorAction SilentlyContinue "
        "| Select-Object Name,Status,StartType;"
        "[PSCustomObject]@{Listeners=$listeners;FirewallProfiles=$fw;RemoteServices=$svc} | ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if not rows:
        fallback = run_command('netstat -ano', shell=True)
        if fallback and isinstance(fallback, list) and '_output' in fallback[0]:
            lines = [ln.strip() for ln in fallback[0]['_output'].splitlines() if ln.strip() and 'LISTENING' in ln.upper()]
            fallback_rows = []
            for ln in lines[:300]:
                parts = re.split(r'\s+', ln)
                if len(parts) >= 5:
                    hint = 'Validate exposed listener and owning process'
                    local_addr = parts[1]
                    local_port = local_addr.split(':')[-1] if ':' in local_addr else None
                    sev, conf = _network_exposure_assessment(
                        section='listeners',
                        risk_hint=hint,
                        local_port=local_port,
                        status=parts[3],
                        expected_ports={135, 445},
                        firewall_permissive=False,
                        service_running=True,
                    )
                    fallback_rows.append({
                        'source': 'netstat_listening',
                        'protocol': parts[0],
                        'local_address': local_addr,
                        'state': parts[3],
                        'pid': parts[4],
                        'risk_hint': hint,
                        'severity': sev,
                        'confidence': conf,
                    })
            sev_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
            fallback_rows.sort(key=lambda r: sev_rank.get(r.get('severity', 'Info'), 0), reverse=True)
            display_and_export('network_exposure_windows', fallback_rows if fallback_rows else [{'status': 'No listening ports found in netstat output'}])
            return
        display_and_export('network_exposure_windows', [{'status': 'Failed', 'error': err}])
        return

    data = rows[0] if rows and isinstance(rows[0], dict) else {}
    out_rows = []

    firewall_profiles = data.get('FirewallProfiles', []) or []
    firewall_permissive = any(
        isinstance(fp, dict)
        and str(fp.get('Enabled', '')).lower() in ('true', '1', 'enabled')
        and str(fp.get('DefaultInboundAction', '')).lower() == 'allow'
        for fp in firewall_profiles
    )

    remote_services = data.get('RemoteServices', []) or []
    svc_running = {str(s.get('Name', '')): str(s.get('Status', '')).lower() == 'running' for s in remote_services if isinstance(s, dict)}
    expected_ports = {135}
    if svc_running.get('LanmanServer'):
        expected_ports.add(445)
    if svc_running.get('TermService'):
        expected_ports.add(3389)
    if svc_running.get('WinRM'):
        expected_ports.update({5985, 5986})

    for item in data.get('Listeners', []) or []:
        if isinstance(item, dict):
            hint = item.get('RiskHint', '')
            port = item.get('LocalPort', '')
            proc_name = item.get('ProcessName', '')
            sev, conf = _network_exposure_assessment(
                section='listeners',
                risk_hint=hint,
                local_port=port,
                status='LISTENING',
                name=proc_name,
                expected_ports=expected_ports,
                firewall_permissive=firewall_permissive,
                service_running=True,
            )
            out_rows.append({
                'section': 'listeners',
                'local_address': item.get('LocalAddress', ''),
                'local_port': port,
                'process': proc_name,
                'pid': item.get('OwningProcess', ''),
                'status': 'LISTENING',
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })
    for item in data.get('FirewallProfiles', []) or []:
        if isinstance(item, dict):
            inbound = str(item.get('DefaultInboundAction', ''))
            hint = 'Review profiles with permissive inbound policy' if inbound.lower() == 'allow' else 'Profile appears restrictive on inbound policy'
            sev, conf = _network_exposure_assessment('firewall_profile', risk_hint=inbound)
            out_rows.append({
                'section': 'firewall_profile',
                'name': item.get('Name', ''),
                'enabled': item.get('Enabled', ''),
                'default_inbound': item.get('DefaultInboundAction', ''),
                'default_outbound': item.get('DefaultOutboundAction', ''),
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })
    for item in data.get('RemoteServices', []) or []:
        if isinstance(item, dict):
            svc_name = str(item.get('Name', ''))
            hint = ''
            if svc_name in ('TermService', 'WinRM', 'LanmanServer', 'RemoteRegistry'):
                hint = 'Remote access service exposed if listening and reachable'
            svc_status = item.get('Status', '')
            sev, conf = _network_exposure_assessment(
                'remote_service',
                risk_hint=hint,
                status=svc_status,
                name=svc_name,
                firewall_permissive=firewall_permissive,
            )
            out_rows.append({
                'section': 'remote_service',
                'name': svc_name,
                'status': svc_status,
                'start_type': item.get('StartType', ''),
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })

    if not out_rows:
        out_rows = [{'status': 'No network exposure records found'}]
    else:
        sev_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        out_rows.sort(key=lambda r: sev_rank.get(r.get('severity', 'Info'), 0), reverse=True)
    display_and_export('network_exposure_windows', out_rows)


def server_network_exposure():
    """Collect Windows Server network exposure with server-relevant ports/services."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"$riskPorts=@(53,88,135,137,138,139,389,445,464,636,3268,3269,3389,5985,5986,80,443,1433,8443);"
        "$listeners=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
        "| ForEach-Object {"
        "$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
        "[PSCustomObject]@{"
        "LocalAddress=$_.LocalAddress;"
        "LocalPort=$_.LocalPort;"
        "OwningProcess=$_.OwningProcess;"
        "ProcessName=if($p){$p.ProcessName}else{'Unknown'};"
        "RiskHint=if($riskPorts -contains [int]$_.LocalPort){'High-value server port exposed'}else{''}"
        "}"
        "};"
        "$fw=Get-NetFirewallProfile -ErrorAction SilentlyContinue "
        "| Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction;"
        "$svc=Get-Service -Name WinRM,TermService,LanmanServer,RemoteRegistry,DNS,KDC,Netlogon,DFSR,NTDS -ErrorAction SilentlyContinue "
        "| Select-Object Name,Status,StartType;"
        "$shares=Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,CurrentUsers,EncryptData,Special;"
        "[PSCustomObject]@{Listeners=$listeners;FirewallProfiles=$fw;CriticalServices=$svc;SmbShares=$shares} | ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if not rows:
        display_and_export('server_network_exposure', [{'status': 'Failed', 'error': err}])
        return

    data = rows[0] if rows and isinstance(rows[0], dict) else {}
    out_rows = []

    firewall_profiles = data.get('FirewallProfiles', []) or []
    firewall_permissive = any(
        isinstance(fp, dict)
        and str(fp.get('Enabled', '')).lower() in ('true', '1', 'enabled')
        and str(fp.get('DefaultInboundAction', '')).lower() == 'allow'
        for fp in firewall_profiles
    )

    critical_services = data.get('CriticalServices', []) or []
    running_services = {
        str(s.get('Name', '')).lower()
        for s in critical_services
        if isinstance(s, dict) and str(s.get('Status', '')).lower() == 'running'
    }
    is_dc = any(x in running_services for x in ('dns', 'kdc', 'netlogon', 'ntds'))
    is_file = 'lanmanserver' in running_services

    listeners = data.get('Listeners', []) or []
    listener_processes = {
        str(l.get('ProcessName', '')).lower()
        for l in listeners
        if isinstance(l, dict)
    }
    is_sql = 'sqlservr' in listener_processes
    is_web = any(p in listener_processes for p in ('w3wp', 'httpd', 'nginx', 'apache2', 'iisexpress', 'svchost'))

    expected_ports = {135, 3389, 5985, 5986}
    if is_dc:
        expected_ports.update({53, 88, 389, 445, 464, 636, 3268, 3269, 139})
    if is_file:
        expected_ports.update({445, 139})
    if is_sql:
        expected_ports.add(1433)
    if is_web:
        expected_ports.update({80, 443, 8080, 8443})

    for item in data.get('Listeners', []) or []:
        if isinstance(item, dict):
            hint = item.get('RiskHint', '')
            port = item.get('LocalPort', '')
            proc_name = item.get('ProcessName', '')
            sev, conf = _network_exposure_assessment(
                section='listeners',
                risk_hint=hint,
                local_port=port,
                status='LISTENING',
                name=proc_name,
                expected_ports=expected_ports,
                firewall_permissive=firewall_permissive,
                service_running=True,
            )
            out_rows.append({
                'section': 'listeners',
                'local_address': item.get('LocalAddress', ''),
                'local_port': port,
                'process': proc_name,
                'pid': item.get('OwningProcess', ''),
                'status': 'LISTENING',
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })
    for item in data.get('FirewallProfiles', []) or []:
        if isinstance(item, dict):
            inbound = str(item.get('DefaultInboundAction', ''))
            hint = 'Server profile allows inbound traffic; verify segmentation' if inbound.lower() == 'allow' else 'Server profile appears restrictive on inbound policy'
            sev, conf = _network_exposure_assessment('firewall_profile', risk_hint=inbound)
            out_rows.append({
                'section': 'firewall_profile',
                'name': item.get('Name', ''),
                'enabled': item.get('Enabled', ''),
                'default_inbound': item.get('DefaultInboundAction', ''),
                'default_outbound': item.get('DefaultOutboundAction', ''),
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })
    for item in data.get('CriticalServices', []) or []:
        if isinstance(item, dict):
            svc_name = item.get('Name', '')
            svc_status = item.get('Status', '')
            hint = 'Server remote/infra service exposure check'
            sev, conf = _network_exposure_assessment(
                'critical_service',
                risk_hint=hint,
                status=svc_status,
                name=svc_name,
                firewall_permissive=firewall_permissive,
            )
            out_rows.append({
                'section': 'critical_service',
                'name': svc_name,
                'status': svc_status,
                'start_type': item.get('StartType', ''),
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })
    for item in data.get('SmbShares', []) or []:
        if isinstance(item, dict):
            hint = 'Review exposed shares and encryption settings'
            sev, conf = _network_exposure_assessment('smb_share', risk_hint=hint, firewall_permissive=firewall_permissive)
            out_rows.append({
                'section': 'smb_share',
                'name': item.get('Name', ''),
                'path': item.get('Path', ''),
                'current_users': item.get('CurrentUsers', ''),
                'encrypt_data': item.get('EncryptData', ''),
                'special': item.get('Special', ''),
                'risk_hint': hint,
                'severity': sev,
                'confidence': conf,
            })

    if not out_rows:
        out_rows = [{'status': 'No server network exposure records found'}]
    else:
        sev_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        out_rows.sort(key=lambda r: sev_rank.get(r.get('severity', 'Info'), 0), reverse=True)
    display_and_export('server_network_exposure', out_rows)


def rdp_enabled_check():
    """Check if RDP is enabled."""
    res = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        out = res[0]['_output']
        if '0x0' in out or '0' in out.split():
            console.print('RDP is enabled.')
        else:
            console.print('RDP is disabled.')
    else:
        console.print('[yellow]Unable to check RDP status.[/yellow]')


def wlan_profiles():
    """Get all WLAN profiles with passwords using netsh command."""
    res = run_command('netsh wlan show profiles', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        output = res[0]['_output']
        console.print('[bold]WLAN Profiles with Passwords:[/bold]')
        profiles = []
        profile_rows = []
        
        # Extract profile names
        for line in output.split('\n'):
            if 'All User Profile' in line:
                try:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        profile_name = parts[1].strip()
                        if profile_name:
                            profiles.append(profile_name)
                except Exception:
                    pass
        
        if not profiles:
            console.print('[yellow]No WLAN profiles found[/yellow]')
            return
        
        # Get detailed info for each profile including password
        for profile_name in profiles:
            console.print(f'\n[bold cyan]Profile:[/bold cyan] {profile_name}')
            password_text = 'Unable to retrieve'
            
            # Get profile details with key in clear text
            res_detail = run_command(f'netsh wlan show profile name="{profile_name}" key=clear', shell=True)
            if res_detail and '_output' in res_detail[0]:
                detail_output = res_detail[0]['_output']
                password_found = False
                
                for detail_line in detail_output.split('\n'):
                    # Look for password in the output
                    if 'Key Content' in detail_line:
                        try:
                            parts = detail_line.split(':', 1)
                            if len(parts) == 2:
                                password = parts[1].strip()
                                if password:
                                    console.print(f'  [bold yellow]Password:[/bold yellow] {password}')
                                    password_text = password
                                    password_found = True
                        except Exception:
                            pass
                
                if not password_found:
                    console.print('  [dim]Password:[/dim] Not found or not available')
                    password_text = 'Not found or not available'
            else:
                console.print('  [dim]Password:[/dim] Unable to retrieve')
            profile_rows.append({'profile_name': profile_name, 'password': password_text})

        choice = console.input('\n[bold]Export to file?[/bold] (y/n): ')
        if choice.lower() == 'y':
            try:
                outdir = Path('outputs')
                outdir.mkdir(exist_ok=True)
                fname = outdir / f'wlan_profiles_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                with open(fname, 'w', encoding='utf-8') as f:
                    f.write('=== WLAN Profiles with Passwords ===\n\n')
                    for row in profile_rows:
                        f.write(f'Profile: {row["profile_name"]}\n')
                        f.write(f'Password: {row["password"]}\n\n')
                console.print(f'[green]Saved to {fname}[/green]')
            except Exception as e:
                console.print(f'[red]Export failed: {e}[/red]')
    else:
        console.print('[red]Failed to retrieve WLAN profiles[/red]')


def _json_rows_from_command(cmd):
    """Run a command that returns JSON and normalize it to list[dict]."""
    res = run_command(cmd, shell=True)
    if not res or not isinstance(res, list):
        return [], 'No response from command'
    if '_error' in res[0]:
        return [], res[0].get('_error', 'Unknown command error')
    out = res[0].get('_output', '')
    if not out:
        return [], 'No output from command'
    try:
        data = json.loads(out)
    except Exception:
        return [], f'Failed to parse JSON output: {out[:300]}'
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)], ''
    if isinstance(data, dict):
        return [data], ''
    return [], 'Command returned non-object JSON'


def _network_exposure_assessment(
    section,
    risk_hint='',
    local_port=None,
    status='',
    name='',
    expected_ports=None,
    firewall_permissive=False,
    service_running=False,
):
    """Return (severity, confidence) for network exposure rows.

    Confidence labels:
    - Expected: common/role-aligned exposure
    - Review: needs analyst validation
    - Suspicious: likely risky or attacker-useful
    """
    risk_text = str(risk_hint or '').lower()
    status_text = str(status or '').lower()
    name_text = str(name or '').lower()
    expected_ports = set(expected_ports or set())

    port = None
    try:
        if local_port is not None and str(local_port).strip() != '':
            port = int(str(local_port))
    except Exception:
        port = None

    critical_ports = {445, 3389, 5985, 5986, 1433, 3306, 5432, 389, 636, 3268, 3269, 88}
    high_ports = {21, 22, 23, 53, 80, 135, 137, 138, 139, 443, 464, 8080, 8443}
    suspicious_proc = {'cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'nc', 'ncat', 'socat'}

    if section == 'listeners':
        proc_susp = any(p == name_text for p in suspicious_proc)
        expected = port in expected_ports if port is not None else False

        if proc_susp:
            return 'High', 'Suspicious'

        # Keep critical only for risky combinations.
        if port in critical_ports and firewall_permissive and service_running and not expected:
            return 'Critical', 'Suspicious'

        if port in critical_ports:
            if expected:
                return 'Medium', 'Expected'
            return 'High', 'Review'

        if port in high_ports:
            if expected:
                return 'Low', 'Expected'
            return 'Medium', 'Review'

        return 'Low', ('Expected' if expected else 'Review')

    if section in ('remote_service', 'critical_service'):
        running = status_text == 'running'
        if running and firewall_permissive and any(s in name_text for s in ('winrm', 'termservice', 'lanmanserver', 'dns', 'kdc', 'ntds', 'netlogon')):
            return 'High', 'Review'
        if running:
            return 'Medium', 'Expected'
        return 'Low', 'Expected'

    if section == 'firewall_profile':
        if 'allow' in risk_text:
            return 'High', 'Suspicious'
        return 'Low', 'Expected'

    if section == 'smb_share':
        if firewall_permissive:
            return 'High', 'Review'
        return 'Medium', 'Review'

    return 'Info', 'Review'


def server_host_context():
    """Collect Windows Server host context and role indicators."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"$os=Get-CimInstance Win32_OperatingSystem;"
        "$cs=Get-CimInstance Win32_ComputerSystem;"
        "[PSCustomObject]@{"
        "ComputerName=$env:COMPUTERNAME;"
        "Caption=$os.Caption;"
        "Version=$os.Version;"
        "InstallDate=$os.InstallDate;"
        "LastBootUpTime=$os.LastBootUpTime;"
        "ProductType=$os.ProductType;"
        "DomainRole=$cs.DomainRole;"
        "PartOfDomain=$cs.PartOfDomain;"
        "Domain=$cs.Domain"
        "} | ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        role_map = {
            0: 'Standalone Workstation',
            1: 'Member Workstation',
            2: 'Standalone Server',
            3: 'Member Server',
            4: 'Backup Domain Controller',
            5: 'Primary Domain Controller',
        }
        product_type_map = {1: 'Workstation', 2: 'Domain Controller', 3: 'Server'}
        for r in rows:
            try:
                r['product_type_label'] = product_type_map.get(int(r.get('ProductType', 0)), 'Unknown')
            except Exception:
                r['product_type_label'] = 'Unknown'
            try:
                r['domain_role_label'] = role_map.get(int(r.get('DomainRole', -1)), 'Unknown')
            except Exception:
                r['domain_role_label'] = 'Unknown'
        display_and_export('server_host_context', rows)
    else:
        display_and_export('server_host_context', [{'status': 'Failed', 'error': err}])


def server_installed_roles():
    """Collect installed Windows Server roles/features."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"Get-WindowsFeature | Where-Object {$_.Installed -eq $true} "
        "| Select-Object Name,DisplayName,InstallState,FeatureType "
        "| ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_installed_roles', rows)
        return

    fallback = run_command('dism /online /Get-Features /Format:Table', shell=True)
    if fallback and isinstance(fallback, list) and '_output' in fallback[0]:
        display_and_export('server_installed_roles', [{'dism_output': fallback[0]['_output'][:10000]}])
    else:
        ferr = fallback[0].get('_error', '') if fallback and isinstance(fallback, list) else ''
        display_and_export('server_installed_roles', [{'status': 'Failed', 'error': err or ferr or 'Unable to collect roles'}])


def server_smb_shares():
    """Collect SMB share configuration."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"Get-SmbShare | Select-Object Name,Path,Description,"
        "CurrentUsers,EncryptData,FolderEnumerationMode,Special,Temporary "
        "| ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_smb_shares', rows)
    else:
        display_and_export('server_smb_shares', [{'status': 'Failed', 'error': err}])


def server_smb_sessions():
    """Collect active SMB sessions from client machines/users."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"Get-SmbSession | Select-Object SessionId,ClientComputerName,"
        "ClientUserName,NumOpens,Dialect,ContinuouslyAvailable "
        "| ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_smb_sessions', rows)
    else:
        display_and_export('server_smb_sessions', [{'status': 'No active sessions or command unavailable', 'error': err}])


def server_ad_critical_services():
    """Collect status of AD/infra-critical services often used on servers."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"Get-Service -Name NTDS,DNS,KDC,Netlogon,DFSR -ErrorAction SilentlyContinue "
        "| Select-Object Name,DisplayName,Status,StartType "
        "| ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_ad_critical_services', rows)
    else:
        display_and_export('server_ad_critical_services', [{'status': 'No AD-critical services found on this host', 'error': err}])


def server_local_admins():
    """Collect local Administrators group membership."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"Get-LocalGroupMember -Group Administrators -ErrorAction Stop "
        "| Select-Object Name,ObjectClass,PrincipalSource,SID "
        "| ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_local_admins', rows)
        return

    fallback = run_command('net localgroup administrators', shell=True)
    if fallback and isinstance(fallback, list) and '_output' in fallback[0]:
        display_and_export('server_local_admins', [{'net_localgroup_output': fallback[0]['_output'][:10000]}])
    else:
        ferr = fallback[0].get('_error', '') if fallback and isinstance(fallback, list) else ''
        display_and_export('server_local_admins', [{'status': 'Failed', 'error': err or ferr or 'Unable to collect admin group membership'}])


def server_recent_account_changes():
    """Collect recent account/group-related security events."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"$ids=@(4720,4722,4723,4724,4725,4726,4728,4732,4740);"
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue "
        "| Select-Object -First 200 TimeCreated,Id,ProviderName,MachineName,Message "
        "| ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        # Trim giant event messages for table readability.
        for r in rows:
            msg = r.get('Message')
            if isinstance(msg, str) and len(msg) > 800:
                r['Message'] = msg[:800] + '...'
        display_and_export('server_recent_account_changes', rows)
    else:
        display_and_export('server_recent_account_changes', [{'status': 'No matching events or command unavailable', 'error': err}])


def server_winrm_config():
    """Collect WinRM service status and listener configuration."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"$svc=Get-Service WinRM -ErrorAction SilentlyContinue;"
        "$listeners=(winrm enumerate winrm/config/listener 2>$null | Out-String);"
        "[PSCustomObject]@{"
        "WinRMStatus=if($svc){$svc.Status}else{'NotFound'};"
        "WinRMStartType=if($svc){$svc.StartType}else{'Unknown'};"
        "Listeners=$listeners"
        "} | ConvertTo-Json -Depth 6\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_winrm_config', rows)
    else:
        display_and_export('server_winrm_config', [{'status': 'Failed', 'error': err}])


def server_rdp_sessions():
    """Collect current RDP/terminal sessions."""
    res = run_command('query user', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        out = res[0]['_output']
        lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()]
        if len(lines) <= 1:
            display_and_export('server_rdp_sessions', [{'status': 'No active user sessions', 'raw_output': out[:2000]}])
            return
        rows = []
        for line in lines[1:]:
            parts = re.split(r'\s{2,}', line.replace('>', '').strip())
            if parts:
                rows.append({
                    'username': parts[0] if len(parts) > 0 else '',
                    'session_name': parts[1] if len(parts) > 1 else '',
                    'id': parts[2] if len(parts) > 2 else '',
                    'state': parts[3] if len(parts) > 3 else '',
                    'idle_time': parts[4] if len(parts) > 4 else '',
                    'logon_time': parts[5] if len(parts) > 5 else '',
                    'raw_line': line,
                })
        display_and_export('server_rdp_sessions', rows if rows else [{'raw_output': out[:5000]}])
    else:
        err = res[0].get('_error', 'query user failed') if res and isinstance(res, list) else 'query user failed'
        display_and_export('server_rdp_sessions', [{'status': 'Failed', 'error': err}])


def server_ad_domain_context():
    """Collect AD domain/forest context in read-only mode."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"try {"
        "Import-Module ActiveDirectory -ErrorAction Stop;"
        "$d=Get-ADDomain; $f=Get-ADForest;"
        "[PSCustomObject]@{"
        "DomainDNSRoot=$d.DNSRoot;"
        "DomainNetBIOS=$d.NetBIOSName;"
        "DomainMode=$d.DomainMode;"
        "ForestRootDomain=$f.RootDomain;"
        "ForestMode=$f.ForestMode;"
        "SchemaMaster=$f.SchemaMaster;"
        "DomainNamingMaster=$f.DomainNamingMaster"
        "} | ConvertTo-Json -Depth 6"
        "} catch { [PSCustomObject]@{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_ad_domain_context', rows)
    else:
        display_and_export('server_ad_domain_context', [{'status': 'Failed', 'error': err}])


def server_ad_domain_controllers():
    """Collect AD domain controller inventory in read-only mode."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"try {"
        "Import-Module ActiveDirectory -ErrorAction Stop;"
        "Get-ADDomainController -Filter * "
        "| Select-Object HostName,IPv4Address,Site,OperatingSystem,IsGlobalCatalog,Enabled "
        "| ConvertTo-Json -Depth 6"
        "} catch { [PSCustomObject]@{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_ad_domain_controllers', rows)
    else:
        display_and_export('server_ad_domain_controllers', [{'status': 'Failed', 'error': err}])


def server_ad_privileged_group_members():
    """Collect AD privileged group members in read-only mode."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"try {"
        "Import-Module ActiveDirectory -ErrorAction Stop;"
        "$groups=@('Domain Admins','Enterprise Admins','Schema Admins','Administrators');"
        "$rows=@();"
        "foreach($g in $groups){"
        "try {"
        "$members=Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop;"
        "foreach($m in $members){$rows += [PSCustomObject]@{Group=$g; Name=$m.Name; SamAccountName=$m.SamAccountName; ObjectClass=$m.objectClass}}"
        "} catch { $rows += [PSCustomObject]@{Group=$g; Name=''; SamAccountName=''; ObjectClass=('Error: ' + $_.Exception.Message)} }"
        "}"
        "$rows | ConvertTo-Json -Depth 6"
        "} catch { [PSCustomObject]@{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_ad_privileged_group_members', rows)
        return

    fallback = run_command('net group "Domain Admins" /domain', shell=True)
    if fallback and isinstance(fallback, list) and '_output' in fallback[0]:
        display_and_export('server_ad_privileged_group_members', [{'domain_admins_output': fallback[0]['_output'][:12000]}])
    else:
        ferr = fallback[0].get('_error', '') if fallback and isinstance(fallback, list) else ''
        display_and_export('server_ad_privileged_group_members', [{'status': 'Failed', 'error': err or ferr or 'Unable to collect AD privileged groups'}])


def server_ad_trusts():
    """Collect AD trust relationships in read-only mode."""
    cmd = (
        "powershell -NoProfile -Command "
        "\"try {"
        "Import-Module ActiveDirectory -ErrorAction Stop;"
        "Get-ADTrust -Filter * "
        "| Select-Object Name,Direction,TrustType,ForestTransitive,IntraForest,Source,Target "
        "| ConvertTo-Json -Depth 6"
        "} catch { [PSCustomObject]@{Error=$_.Exception.Message} | ConvertTo-Json -Depth 6 }\""
    )
    rows, err = _json_rows_from_command(cmd)
    if rows:
        display_and_export('server_ad_trusts', rows)
    else:
        display_and_export('server_ad_trusts', [{'status': 'Failed', 'error': err}])

def defender_status():
    """Check Windows Defender status."""
    res = run_command('powershell -command "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled, RealTimeProtectionEnabled"', shell=True)
    if res and isinstance(res, list) and '_output' in res[0]:
        console.print('Windows Defender Status:')
        console.print(res[0]['_output'])
    else:
        console.print('[yellow]Unable to check Defender status.[/yellow]')


def main():
    # Professional banner with bold PARTHASARATHI
    banner = """
    ╔═════════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                     ║                                                                                                                              
    ║                                                                                     ║
    ║    ▄▄▄▄▄▄▄                    ▄▄                                        ▄▄          ║
    ║    ███▀▀███▄             ██   ██                                   ██   ██    ▀▀    ║
    ║    ███▄▄███▀ ▀▀█▄ ████▄ ▀██▀▀ ████▄  ▀▀█▄ ▄█▀▀▀  ▀▀█▄ ████▄  ▀▀█▄ ▀██▀▀ ████▄ ██    ║ 
    ║    ███▀▀▀▀  ▄█▀██ ██ ▀▀  ██   ██ ██ ▄█▀██ ▀███▄ ▄█▀██ ██ ▀▀ ▄█▀██  ██   ██ ██ ██    ║
    ║    ███      ▀█▄██ ██     ██   ██ ██ ▀█▄██ ▄▄▄█▀ ▀█▄██ ██    ▀█▄██  ██   ██ ██ ██▄   ║
    ║                                                                                     ║                                                                                     
    ║                                                                                     ║
    ║               [DFIR | THREAT HUNTING | Detect | Respond | Investigate]              ║
    ║                                                                                     ║
    ║           Guiding the defenders through the battlefield of cyber threats.           ║
    ║                                                                                     ║
    ║                            Developed by Asim Tara Pathak                            ║
    ║                                                                                     ║
    ╚═════════════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold bright_green")
    console.print(
        f"[bold cyan]Platform detected:[/bold cyan] {PLATFORM_RUNTIME.display_name} "
        f"| support: {PLATFORM_RUNTIME.support_level}"
    )
    console.print(f"[dim]{PLATFORM_RUNTIME.note}[/dim]")

    is_windows_family = PLATFORM_RUNTIME.os_key in ('windows', 'windows-server')

    while True:
        console.print('\nMain Menu:')
        if is_windows_family:
            console.print('1. Run artifact queries')
            console.print('2. Browser artifacts')
            console.print('3. Incident Response actions')
            console.print('4. Diagnostic & readiness check')
            console.print('5. YARA IOC finder')
            console.print('6. Exit')
            choice = console.input('Choose (1-6): ')
        else:
            console.print('1. Run artifact queries')
            console.print('2. Browser artifacts')
            console.print('3. Incident Response actions')
            console.print('4. Diagnostic & readiness check')
            console.print('5. YARA IOC finder')
            console.print('6. Exit')
            choice = console.input('Choose (1-6): ')

        if choice == '1':
            artifact_collection_menu()
        elif choice == '2' and is_windows_family:
            browser_artifacts_menu()
        elif choice == '3' and is_windows_family:
            incident_response_menu()
        elif choice == '4' and is_windows_family:
            readiness_check()  # This calls diagnostic internally
        elif choice == '5' and is_windows_family:
            yara_ioc_menu()
        elif choice == '2' and PLATFORM_RUNTIME.os_key in ('linux', 'macos'):
            browser_artifacts_menu()
        elif choice == '3' and PLATFORM_RUNTIME.os_key == 'linux':
            incident_response_menu_linux()
        elif choice == '3' and PLATFORM_RUNTIME.os_key == 'macos':
            incident_response_menu_macos()
        elif choice == '4' and PLATFORM_RUNTIME.os_key in ('linux', 'macos'):
            readiness_check()
        elif choice == '5' and PLATFORM_RUNTIME.os_key in ('linux', 'macos'):
            yara_ioc_menu()
        else:
            break


if __name__ == '__main__':
    main()
