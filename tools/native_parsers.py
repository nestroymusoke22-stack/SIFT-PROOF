import os
import sys
from datetime import datetime, timezone
 
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
 
 
# ── Layout discovery ──────────────────────────────────────────────────────────
 
def find_windows_root(root):
    """
    Given a mount point, return the directory that directly contains the
    'Windows' folder. Handles mounts that expose the volume root, or a parent
    holding 'C/' style sub-folders. Falls back to the input root.
    """
    if not root or not os.path.isdir(root):
        return root
    # Direct hit
    if os.path.isdir(os.path.join(root, 'Windows')):
        return root
    # One level down (e.g. /mnt/x/C/Windows)
    try:
        for entry in os.listdir(root):
            sub = os.path.join(root, entry)
            if os.path.isdir(sub) and os.path.isdir(os.path.join(sub, 'Windows')):
                return sub
    except OSError:
        pass
    return root
 
 
def _case_insensitive_join(base, *parts):
    """Resolve a path under `base` ignoring case (NTFS is case-insensitive)."""
    cur = base
    for part in parts:
        if not os.path.isdir(cur):
            return os.path.join(cur, part)
        if os.path.exists(os.path.join(cur, part)):
            cur = os.path.join(cur, part)
            continue
        match = None
        try:
            for entry in os.listdir(cur):
                if entry.lower() == part.lower():
                    match = entry
                    break
        except OSError:
            pass
        cur = os.path.join(cur, match if match else part)
    return cur
 
 
def _fmt_ts(epoch):
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except (OverflowError, OSError, ValueError):
        return ''
 
 
def _ok(table, inserted, raw_hash, schema, message, extra=None):
    out = {
        "status": "success", "table": table,
        "rows_inserted": inserted, "sha256": raw_hash,
        "schema": schema, "message": message,
        "source_tool": "native-python",
    }
    if extra:
        out.update(extra)
    return out
 
 
# ── MFT timeline (native: os.walk over the live mount) ─────────────────────────
 
def native_mft(root, max_files=20000):
    win_root = find_windows_root(root)
    raw_lines = []
    rows = []
    for dirpath, _dirs, files in os.walk(win_root):
        if len(rows) >= max_files:
            break
        for name in files:
            if len(rows) >= max_files:
                break
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            created = _fmt_ts(getattr(st, 'st_ctime', 0))
            modified = _fmt_ts(getattr(st, 'st_mtime', 0))
            accessed = _fmt_ts(getattr(st, 'st_atime', 0))
            rows.append((name, full, created, modified, accessed,
                         int(getattr(st, 'st_size', 0)), 'create'))
            raw_lines.append(f"{full}|{modified}|{st.st_size}")
 
    h = hash_raw_output('\n'.join(raw_lines))
    inserted = 0
    conn = get_connection()
    c = conn.cursor()
    for r in rows:
        try:
            c.execute(
                '''INSERT INTO mft_events
                   (filename, full_path, created_at, modified_at, accessed_at,
                    file_size, action, source_tool, sha256_of_raw_output)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (*r, 'native-walk', h))
            inserted += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
 
    return _ok(
        "mft_events", inserted, h,
        {"filename": "str", "full_path": "str", "created_at": "datetime",
         "modified_at": "datetime", "accessed_at": "datetime",
         "file_size": "int", "action": "str"},
        (f"{inserted} live file records walked from {win_root}. "
         "Timestamps are real filesystem MAC times. Filter with "
         "full_path LIKE '%\\\\AppData\\\\%' or filename LIKE '%.exe'."))
 
 
# ── Prefetch (native: .pf filename + real mtime) ───────────────────────────────
 
def _parse_pf_name(pf_filename):
    """EVIL.EXE-AB12CD34.pf → EVIL.EXE (keeps the original .pf as stored name)."""
    base = pf_filename
    if base.lower().endswith('.pf'):
        base = base[:-3]
    if '-' in base:
        base = base.rsplit('-', 1)[0]
    return base
 
 
def native_prefetch(root):
    win_root = find_windows_root(root)
    pref_dir = _case_insensitive_join(win_root, 'Windows', 'Prefetch')
    if not os.path.isdir(pref_dir):
        return _ok("prefetch_events", 0, "empty",
                   {"executable_name": "str", "last_run_time": "datetime",
                    "run_count": "int"},
                   f"No Prefetch directory found under {win_root}.")
 
    pf_files = [f for f in os.listdir(pref_dir) if f.lower().endswith('.pf')]
    raw_lines = []
    inserted = 0
    conn = get_connection()
    c = conn.cursor()
    for f in pf_files:
        full = os.path.join(pref_dir, f)
        try:
            st = os.stat(full)
            last_run = _fmt_ts(st.st_mtime)
        except OSError:
            last_run = ''
        raw_lines.append(f"{f}|{last_run}")
        try:
            c.execute(
                '''INSERT INTO prefetch_events
                   (executable_name, last_run_time, run_count, source_tool,
                    sha256_of_raw_output)
                   VALUES (?,?,?,?,?)''',
                (f, last_run, 1, 'native-pf', hash_raw_output(f)))
            inserted += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
 
    h = hash_raw_output('\n'.join(raw_lines))
    return _ok(
        "prefetch_events", inserted, h,
        {"executable_name": "str (e.g. EVIL.EXE-AB12CD34.pf)",
         "last_run_time": "datetime (from .pf mtime)", "run_count": "int"},
        (f"{inserted} prefetch (.pf) execution signatures read from {pref_dir}. "
         "Prefetch proves execution even after the binary is deleted. "
         "Match with executable_name LIKE '%EVIL%'."))
 
 
# ── Registry helpers (python-registry) ─────────────────────────────────────────
 
def _open_hive(path):
    from Registry import Registry
    return Registry.Registry(path)
 
 
def _iter_run_values(reg, hive_label, subkey_path):
    """Yield (key_path, value_name, value_data) for a Run-style key."""
    try:
        key = reg.open(subkey_path)
    except Exception:
        return
    key_path = f"{hive_label}\\{subkey_path}"
    try:
        for v in key.values():
            try:
                yield key_path, v.name(), str(v.value())
            except Exception:
                continue
    except Exception:
        return
 
 
def native_registry_run(root):
    win_root = find_windows_root(root)
    inserted = 0
    raw_lines = []
    conn = get_connection()
    c = conn.cursor()
 
    targets = []  # (hive_path, hive_label, [subkey_paths])
    software = _case_insensitive_join(win_root, 'Windows', 'System32', 'config', 'SOFTWARE')
    if os.path.isfile(software):
        targets.append((software, 'HKLM', [
            'Microsoft\\Windows\\CurrentVersion\\Run',
            'Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
        ]))
 
    users_dir = _case_insensitive_join(win_root, 'Users')
    if os.path.isdir(users_dir):
        for user in os.listdir(users_dir):
            ntuser = os.path.join(users_dir, user, 'NTUSER.DAT')
            if os.path.isfile(ntuser):
                targets.append((ntuser, f'HKCU\\{user}', [
                    'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                ]))
 
    for hive_path, label, subkeys in targets:
        try:
            reg = _open_hive(hive_path)
        except Exception:
            continue
        for sub in subkeys:
            for key_path, value_name, value_data in _iter_run_values(reg, label, sub):
                raw_lines.append(f"{key_path}|{value_name}|{value_data}")
                try:
                    c.execute(
                        '''INSERT INTO registry_runkeys
                           (hive, key_path, value_name, value_data, source_tool,
                            sha256_of_raw_output)
                           VALUES (?,?,?,?,?,?)''',
                        (label.split('\\')[0], key_path, value_name, value_data,
                         'native-registry', hash_raw_output(value_data)))
                    inserted += 1
                except Exception:
                    continue
    conn.commit()
    conn.close()
 
    h = hash_raw_output('\n'.join(raw_lines))
    return _ok(
        "registry_runkeys", inserted, h,
        {"hive": "str (HKLM/HKCU)", "key_path": "str", "value_name": "str",
         "value_data": "str (usually a binary path)"},
        (f"{inserted} registry Run/RunOnce persistence entries parsed natively. "
         "Suspicious: value_data pointing outside System32/Program Files, or to "
         "AppData/Temp."))
 
 
# ── Amcache (python-registry over Amcache.hve) ─────────────────────────────────
 
def _amcache_hive_path(win_root):
    for parts in (
        ('Windows', 'AppCompat', 'Programs', 'Amcache.hve'),
        ('Windows', 'appcompat', 'Programs', 'Amcache.hve'),
    ):
        p = _case_insensitive_join(win_root, *parts)
        if os.path.isfile(p):
            return p
    return None
 
 
def native_amcache(root):
    win_root = find_windows_root(root)
    hive_path = _amcache_hive_path(win_root)
    if not hive_path:
        return _ok("amcache_entries", 0, "empty",
                   {"program_name": "str", "program_path": "str",
                    "sha256_hash": "str", "first_run_time": "datetime"},
                   f"No Amcache.hve found under {win_root}.")
 
    try:
        reg = _open_hive(hive_path)
    except Exception as e:
        return {"status": "error", "table": "amcache_entries",
                "rows_inserted": 0, "error": f"Amcache hive open failed: {e}"}
 
    entries = []
    raw_lines = []
 
    def _val(key, name):
        try:
            return str(key.value(name).value())
        except Exception:
            return ''
 
    # Windows 10+ layout: Root\InventoryApplicationFile
    for root_path, name_val, path_val, sha_val, ts_attr in (
        ('Root\\InventoryApplicationFile', 'Name', 'LowerCaseLongPath', 'FileId', True),
        ('Root\\File', '15', '15', '101', True),
    ):
        try:
            base = reg.open(root_path)
        except Exception:
            continue
        # File layout nests one level (volume GUID) deeper than Inventory layout
        subkeys = []
        if root_path.endswith('File'):
            for vol in base.subkeys():
                subkeys.extend(list(vol.subkeys()))
        else:
            subkeys = list(base.subkeys())
 
        for k in subkeys:
            name = _val(k, name_val)
            path = _val(k, path_val)
            sha = _val(k, sha_val)
            if sha.startswith('0000') and len(sha) > 40:
                sha = sha[4:]   # Amcache prefixes SHA1 with 4 zero bytes
            try:
                first_run = k.timestamp().strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                first_run = ''
            display = name or (os.path.basename(path) if path else '')
            if not display and not path:
                continue
            entries.append((display, path, sha, first_run))
            raw_lines.append(f"{display}|{path}|{sha}|{first_run}")
        if entries:
            break  # use whichever layout produced data
 
    inserted = 0
    conn = get_connection()
    c = conn.cursor()
    for display, path, sha, first_run in entries:
        try:
            c.execute(
                '''INSERT INTO amcache_entries
                   (program_name, program_path, sha256_hash, first_run_time,
                    source_tool, sha256_of_raw_output)
                   VALUES (?,?,?,?,?,?)''',
                (display, path, sha, first_run, 'native-amcache',
                 hash_raw_output(f"{display}{path}{sha}")))
            inserted += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
 
    h = hash_raw_output('\n'.join(raw_lines))
    return _ok(
        "amcache_entries", inserted, h,
        {"program_name": "str", "program_path": "str",
         "sha256_hash": "str (Amcache stores SHA1)", "first_run_time": "datetime"},
        (f"{inserted} Amcache execution records parsed from {os.path.basename(hive_path)}. "
         "Amcache proves a binary existed/ran; cross-reference program_path with MFT."))
 
 
# ── EVTX (python-evtx) ─────────────────────────────────────────────────────────
 
KEY_EVENT_IDS = [4624, 4625, 4648, 4688, 4698, 4720, 4732, 7045, 1102]
 
 
def _evtx_logs_dir(win_root):
    return _case_insensitive_join(win_root, 'Windows', 'System32', 'winevt', 'Logs')
 
 
def _xml_text(xml, tag):
    """Tiny tag extractor that tolerates namespaces/attributes."""
    import re
    m = re.search(rf'<{tag}[^>]*>(.*?)</{tag}>', xml, re.DOTALL)
    return m.group(1).strip() if m else ''
 
 
def native_evtx(root, event_ids=None):
    if event_ids is None:
        event_ids = KEY_EVENT_IDS
    event_ids = set(int(e) for e in event_ids)
 
    win_root = find_windows_root(root)
    logs_dir = _evtx_logs_dir(win_root)
    if not os.path.isdir(logs_dir):
        return _ok("evtx_events", 0, "empty",
                   {"event_id": "int", "timestamp": "datetime", "computer": "str",
                    "username": "str", "description": "str"},
                   f"No winevt/Logs directory found under {win_root}.")
 
    from Evtx.Evtx import Evtx
 
    wanted_logs = ('Security.evtx', 'System.evtx', 'Application.evtx',
                   'Microsoft-Windows-Sysmon%4Operational.evtx')
    available = {f.lower(): f for f in os.listdir(logs_dir)
                 if f.lower().endswith('.evtx')}
    to_parse = [available[w.lower()] for w in wanted_logs
                if w.lower() in available] or list(available.values())
 
    rows = []
    raw_lines = []
    import re
    for log_name in to_parse:
        path = os.path.join(logs_dir, log_name)
        try:
            with Evtx(path) as log:
                for record in log.records():
                    try:
                        xml = record.xml()
                    except Exception:
                        continue
                    m = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
                    if not m:
                        continue
                    eid = int(m.group(1))
                    if event_ids and eid not in event_ids:
                        continue
                    tm = re.search(r'<TimeCreated[^>]*SystemTime="([^"]+)"', xml)
                    ts = tm.group(1).replace('T', ' ')[:19] if tm else ''
                    computer = _xml_text(xml, 'Computer')
                    user = ''
                    um = re.search(
                        r'<Data Name="(?:TargetUserName|SubjectUserName)">([^<]*)</Data>',
                        xml)
                    if um:
                        user = um.group(1)
                    desc = f"{log_name} EventID {eid}"
                    rows.append((eid, ts, computer, user, desc))
                    raw_lines.append(f"{eid}|{ts}|{computer}|{user}")
        except Exception:
            continue
 
    inserted = 0
    conn = get_connection()
    c = conn.cursor()
    for eid, ts, computer, user, desc in rows:
        try:
            c.execute(
                '''INSERT INTO evtx_events
                   (event_id, timestamp, computer, username, description,
                    source_tool, sha256_of_raw_output)
                   VALUES (?,?,?,?,?,?,?)''',
                (eid, ts, computer, user, desc, 'native-evtx',
                 hash_raw_output(f"{eid}{ts}{user}")))
            inserted += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
 
    h = hash_raw_output('\n'.join(raw_lines))
    return _ok(
        "evtx_events", inserted, h,
        {"event_id": "int", "timestamp": "datetime", "computer": "str",
         "username": "str", "description": "str"},
        (f"{inserted} Windows event-log records parsed natively. Key IDs: "
         "4688=process_create, 4624=logon, 4625=failed_logon, 7045=service_install, "
         "1102=audit_log_cleared, 4720=account_created."))