import json
import shutil
import subprocess
import platform
from pathlib import Path
from rich.table import Table
from rich.markup import escape

OSQUERY_WINDOWS = Path('bin') / 'windows' / 'osqueryi.exe'
OSQUERY_WINDOWS_ALT = Path('bin') / 'windows' / 'osquery.exe'
OSQUERY_LINUX = Path('bin') / 'linux' / 'osqueryi'
OSQUERY_MACOS = Path('bin') / 'macos' / 'osqueryi'
OSQUERY_MACOS_DAEMON = Path('bin') / 'macos' / 'osqueryd'


def find_osquery():
    system = platform.system().lower()

    if system == 'linux':
        if OSQUERY_LINUX.exists():
            return str(OSQUERY_LINUX)
        return 'osqueryi'

    if system == 'darwin':
        if OSQUERY_MACOS.exists():
            return str(OSQUERY_MACOS)
        if OSQUERY_MACOS_DAEMON.exists():
            return str(OSQUERY_MACOS_DAEMON)
        return 'osqueryi'

    if system.startswith('win'):
        if OSQUERY_WINDOWS.exists():
            return str(OSQUERY_WINDOWS)
        if OSQUERY_WINDOWS_ALT.exists():
            return str(OSQUERY_WINDOWS_ALT)
        # fallback to system path on Windows only
        return 'osqueryi'

    # Other platforms: use PATH-resolved osqueryi only.
    return 'osqueryi'


def run_osquery(artifact_name_or_query):
    """If artifact_name_or_query looks like a key from queries.ARTIFACTS,
    caller should pass the actual SQL. Here we accept either raw SQL or a key.
    The caller (parthasarathi) will pass the key and look up the SQL.
    For convenience, if a simple name is passed this function tries to read
    from queries.ARTIFACTS dynamically.
    """
    try:
        from queries import ARTIFACTS
    except Exception:
        ARTIFACTS = {}

    if artifact_name_or_query in ARTIFACTS:
        sql = ARTIFACTS[artifact_name_or_query]['query']
    else:
        sql = artifact_name_or_query

    exe = find_osquery()
    exe_name = Path(exe).name.lower()
    # Build command candidates. osqueryi supports --json -q <SQL>.
    # Some macOS bundles only ship osqueryd; try ephemeral shell-compatible patterns.
    if exe_name == 'osqueryd':
        cmd_candidates = [
            [exe, '--ephemeral', '--disable_watchdog', '--allow_unsafe', '--disable_extensions', '--json', '-q', sql],
            [exe, '--ephemeral', '--disable_watchdog', '--allow_unsafe', '--disable_extensions', '--json', sql],
            [exe, '--json', '-q', sql],
            [exe, '--json', sql],
        ]
    else:
        cmd_candidates = [
            [exe, '--json', '-q', sql],
            [exe, '--json', sql],
        ]

    last_err = ''
    for cmd in cmd_candidates:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
        except FileNotFoundError:
            last_err = f'osquery binary not found at {exe}. Put osqueryi/osqueryd in bin/<platform> or in PATH'
            continue
        except PermissionError:
            last_err = f'Permission denied executing {exe}. Ensure the binary is executable (chmod +x) and allowed by macOS security settings.'
            continue
        if res.returncode != 0:
            last_err = (res.stderr or res.stdout or '').strip()
            continue
        out = res.stdout.strip()
        if not out:
            return []
        try:
            data = json.loads(out)
            return data
        except json.JSONDecodeError:
            return [{'_output': out}]
    # return error info instead of raising to keep CLI running
    if exe_name == 'osqueryd' and last_err:
        last_err = f'{last_err} (Tried osqueryd query modes. If this persists, install/use osqueryi on macOS or ensure osqueryd supports --ephemeral query execution.)'
    return [{'_error': last_err or 'osquery failed with unknown error'}]


def run_command(cmd, shell=False):
    """Run an arbitrary command and return structured result.

    Returns a list of dicts; if command failed returns a dict with '_error' and 'stderr'.
    """
    try:
        if isinstance(cmd, str) and not shell:
            # prefer list when possible
            proc = subprocess.run(cmd, capture_output=True, text=True, shell=True, encoding='utf-8', errors='replace')
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, shell=shell, encoding='utf-8', errors='replace')
    except FileNotFoundError as e:
        return [{'_error': str(e)}]
    out = proc.stdout or ''
    err = proc.stderr or ''
    if proc.returncode != 0:
        return [{'_error': err.strip() or out.strip() or f'returncode {proc.returncode}'}]
    # return whole output as single dict for now
    return [{'_output': out.strip()}]


def find_procdump():
    p = Path('bin') / 'windows' / 'procdump.exe'
    if p.exists():
        return str(p)
    return shutil.which('procdump')


def json_to_table(data):
    table = Table(show_lines=False)
    if not data:
        return table
    # build columns from keys of first row
    first = data[0]
    for k in first.keys():
        table.add_column(escape(str(k)))
    for row in data:
        table.add_row(*[escape(str(row.get(k, ''))) for k in first.keys()])
    return table


def export_dataframe(data, outpath):
    import pandas as pd
    outpath = Path(outpath)
    df = pd.DataFrame(data)
    if outpath.suffix == '.csv':
        df.to_csv(outpath, index=False)
    elif outpath.suffix == '.json':
        df.to_json(outpath, orient='records', indent=2)
    elif outpath.suffix in ('.xls', '.xlsx'):
        df.to_excel(outpath, index=False)
    elif outpath.suffix == '.pdf':
        # simple PDF table via reportlab
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table as PDFTable, TableStyle
            from reportlab.lib import colors

            doc = SimpleDocTemplate(str(outpath), pagesize=letter)
            data_tbl = [list(df.columns)] + df.fillna('').astype(str).values.tolist()
            t = PDFTable(data_tbl)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ]))
            doc.build([t])
        except Exception:
            # fallback: save as csv
            df.to_csv(outpath.with_suffix('.csv'), index=False)
