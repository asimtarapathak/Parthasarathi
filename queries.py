"""
Collection of artifact queries for Windows using osquery.
Each key maps to a dict with 'desc' and 'query'.
"""

ARTIFACTS = {
    'processes': {
        'desc': 'Running processes',
        'query': 'SELECT pid, name, path, cmdline, uid, gid, on_disk FROM processes;'
    },
    'services': {
        'desc': 'Windows services',
        'query': 'SELECT name, display_name, path, pid, start_type, state FROM services;'
    },
    'scheduled_tasks': {
        'desc': 'Scheduled tasks',
        'query': 'SELECT * FROM scheduled_tasks;'
    },
    'autoruns_registry': {
        'desc': 'Autoruns from registry',
        'query': "SELECT * FROM registry WHERE key LIKE '%\\\\Run%';"
    },
    'drivers': {
        'desc': 'Loaded kernel drivers',
        'query': 'SELECT name, path, description FROM kernel_modules;'
    },
    'process_open_sockets': {
        'desc': 'Open sockets by process',
        'query': 'SELECT pid, fd, local_address, local_port, remote_address, remote_port, family, protocol FROM process_open_sockets;'
    },
    'network_interface': {
        'desc': 'Network interfaces and addresses',
        'query': 'SELECT * FROM interface_addresses;'
    },
    'arp_cache': {
        'desc': 'ARP cache',
        'query': 'SELECT * FROM arp_cache;'
    },
    'usb_devices': {
        'desc': 'Connected USB devices',
        'query': "SELECT * FROM usb_devices;"
    },
    'powershell_events': {
        'desc': 'Powershell scriptblock logging (Event Log)',
        'query': "SELECT * FROM windows_eventlog WHERE channel='Microsoft-Windows-PowerShell/Operational' LIMIT 200;"
    },
    'lsass_handles': {
        'desc': 'Processes accessing lsass (heuristic)',
        'query': "SELECT name, pid, cmdline FROM processes WHERE lower(cmdline) LIKE '%lsass%' AND name NOT LIKE '%osquery%';"
    },
    'file_changes_recent': {
        'desc': 'Recently modified files in C:\\Users',
        'query': "SELECT path, size, mtime FROM file WHERE path LIKE 'C:%\\\\Users%\\\\%' ORDER BY mtime DESC LIMIT 200;"
    },
    'listening_ports': {
        'desc': 'Listening ports with process names',
        'query': 'SELECT pid, port, address, protocol, path FROM listening_ports;'
    },
    'users': {
        'desc': 'Local user accounts',
        'query': 'SELECT uid, username, type, description FROM users;'
    },
    'logged_in_users': {
        'desc': 'Currently logged-in users',
        'query': 'SELECT username, type, pid FROM logged_in_users;'
    },
    'mounted_filesystems': {
        'desc': 'Mounted filesystems',
        'query': 'SELECT * FROM mounts;'
    },
    'windows_eventlog': {
        'desc': 'Recent Windows Event Log entries (System)',
        'query': "SELECT * FROM windows_eventlog WHERE channel='System' LIMIT 200;"
    },
    'amcache': {
        'desc': 'Amcache entries (if available)',
        'query': "SELECT * FROM amcache;"
    },
    'shimcache': {
        'desc': 'ShimCache (AppCompatCache) entries',
        'query': "SELECT * FROM shim_cache;"
    },
    'firefox_addons': {
        'desc': 'Firefox installed add-ons',
        'query': "SELECT * FROM firefox_addons;"
    },
    'autoruns_startupfolders': {
        'desc': 'Startup folder items',
        'query': "SELECT * FROM startup_items;"
    },
    'firewall_rules': {
        'desc': 'Windows firewall rules',
        'query': "SELECT * FROM windows_firewall_rules;"
    },
    'network_routes': {
        'desc': 'Network routing table',
        'query': "SELECT * FROM routes;"
    },
    'installed_programs': {
        'desc': 'Installed programs with versions',
        'query': "SELECT name, version, install_location, install_date FROM programs;"
    },
    'registry_autoruns': {
        'desc': 'Registry-based autoruns',
        'query': "SELECT key, name, type, data FROM registry WHERE key LIKE '%\\\\Run%' OR key LIKE '%\\\\RunOnce%';"
    },
    'event_logs': {
        'desc': 'Recent Windows event logs (security)',
        'query': "SELECT datetime, eventid, provider_name, channel, data FROM windows_eventlog WHERE channel='Security' ORDER BY datetime DESC LIMIT 100;"
    },
    'browser_downloads': {
        'desc': 'Browser download history',
        'query': "SELECT * FROM chrome_downloads UNION SELECT * FROM firefox_downloads;"
    },
    'ransomware_suspects': {
        'desc': 'Files with double extensions (potential ransomware)',
        'query': "SELECT path, size, mtime, ctime FROM file WHERE path LIKE '%.%.%' AND directory NOT LIKE '%\\\\Windows%' AND directory NOT LIKE '%\\\\Program Files%' ORDER BY mtime DESC LIMIT 500;"
    },
    'shellbags': {
        'desc': 'ShellBags from registry (user activity)',
        'query': "SELECT key, name, type, data FROM registry WHERE key LIKE '%\\\\ShellBags%';"
    },
    'jumplists': {
        'desc': 'JumpList files in user directories',
        'query': "SELECT path, size, mtime FROM file WHERE path LIKE '%\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Recent\\\\AutomaticDestinations%' AND path LIKE '%.automaticDestinations-ms';"
    },
    'lnk_files': {
        'desc': 'LNK shortcut files',
        'query': "SELECT path, size, mtime FROM file WHERE path LIKE '%.lnk' ORDER BY mtime DESC LIMIT 200;"
    },
    'ifeo': {
        'desc': 'Image File Execution Options (IFEO) from registry',
        'query': "SELECT key, name, type, data FROM registry WHERE key LIKE '%\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options%';"
    },
    'wlan_profiles': {
        'desc': 'WLAN profiles',
        'query': "SELECT * FROM wifi_networks;"
    },
    'rdp_logs': {
        'desc': 'RDP connection events from event logs',
        'query': "SELECT datetime, eventid, provider_name, channel, data FROM windows_eventlog WHERE channel='Security' AND eventid IN (4624,4625) AND data LIKE '%RDP%' ORDER BY datetime DESC LIMIT 50;"
    },
    'proxy_settings': {
        'desc': 'Proxy settings from registry',
        'query': "SELECT key, name, type, data FROM registry WHERE key LIKE '%\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings%';"
    },
    'usb_deviceclasses': {
        'desc': 'USB device classes from registry',
        'query': "SELECT key, name, type, data FROM registry WHERE key LIKE '%\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\DeviceClasses%';"
    },
    'mounted_devices': {
        'desc': 'Mounted devices from registry',
        'query': "SELECT key, name, type, data FROM registry WHERE key LIKE '%\\\\SYSTEM\\\\MountedDevices%';"
    },
    'suspicious_autoruns': {
        'desc': 'Suspicious autoruns (unknown sources)',
        'query': "SELECT name, path, args, type, source, uid FROM startup_items WHERE source NOT LIKE '%Startup%' AND source NOT LIKE '%Registry%';"
    },
    'powershell_history': {
        'desc': 'PowerShell command history',
        'query': "SELECT path, size, mtime FROM file WHERE path LIKE '%\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\PowerShell\\\\PSReadLine\\\\ConsoleHost_history.txt%';"
    },
    'executables_appdata': {
        'desc': 'Executables in AppData directories',
        'query': "SELECT path, size, mtime FROM file WHERE (path LIKE '%\\\\AppData%' OR path LIKE '%\\\\Local Settings%') AND (path LIKE '%.exe' OR path LIKE '%.dll') ORDER BY mtime DESC LIMIT 200;"
    },
    'processes_downloads': {
        'desc': 'Processes running from Downloads folders',
        'query': "SELECT pid, name, path, cmdline FROM processes WHERE path LIKE '%\\\\Downloads%' ORDER BY pid;"
    },
    'processes_temp': {
        'desc': 'Processes running from Temp directories',
        'query': "SELECT pid, name, path, cmdline FROM processes WHERE path LIKE '%\\\\Temp%' OR path LIKE '%\\\\tmp%' ORDER BY pid;"
    },
}
