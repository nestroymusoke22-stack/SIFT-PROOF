import subprocess
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
from core.sanitizer import sanitize_args


# ── Volatility3 discovery ─────────────────────────────────────────────────────

def _find_vol():
    """Find the Volatility3 binary on this system."""
    for cmd in ['vol', 'vol3', 'volatility3']:
        try:
            r = subprocess.run(
                [cmd, '--help'], capture_output=True, timeout=10
            )
            if r.returncode in (0, 1):   # vol --help returns 1 on some versions
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    # Last resort: python module
    try:
        r = subprocess.run(
            ['python3', '-m', 'volatility3', '--help'],
            capture_output=True, timeout=10
        )
        if r.returncode in (0, 1):
            return 'python3 -m volatility3'
    except Exception:
        pass
    return None


def _run_vol(image_path, plugin, timeout=600):
    """
    Execute a Volatility3 plugin.
    Returns (stdout_string, error_string_or_None).
    """
    vol = _find_vol()
    if not vol:
        return None, (
            "Volatility3 not found. Install: pip3 install volatility3 "
            "OR: sudo apt-get install python3-volatility3"
        )

    if vol == 'python3 -m volatility3':
        args = ['python3', '-m', 'volatility3', '-f', image_path, plugin]
    else:
        args = [vol, '-f', image_path, plugin]

    # Sanitize before subprocess
    safe, reason = sanitize_args(args)
    if not safe:
        return None, reason

    print(f"[VOL] Running: {' '.join(args)}")
    print(f"[VOL] This may take 2-5 minutes on first run (symbol resolution)...")

    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        if result.stdout.strip():
            return result.stdout, None
        if result.stderr:
            # Volatility3 prints progress to stderr — check if stdout is empty
            # due to no results vs a real error
            if 'Unsatisfied requirement' in result.stderr:
                return None, f"Plugin requirement error: {result.stderr[:300]}"
            if 'No suitable address space' in result.stderr:
                return None, (
                    "Memory image format not recognised. "
                    "Confirm the file is a raw memory dump (not a disk image)."
                )
            # Otherwise stderr is just progress noise — return empty but no error
            return "", None
        return result.stdout, None
    except subprocess.TimeoutExpired:
        return None, f"Timeout after {timeout}s. Try a smaller memory image."
    except FileNotFoundError:
        return None, "Volatility3 binary not found after validation."


# ── Tab-separated output parser helper ───────────────────────────────────────

def _parse_tsv(raw, required_headers_contain):
    """
    Parse Volatility3 tab-separated output.
    Skips Volatility banner lines and progress lines.
    Returns (headers_list, list_of_row_dicts).
    """
    lines = raw.strip().split('\n')
    header_idx = None
    for i, line in enumerate(lines):
        # Volatility3 headers contain these tokens
        if any(tok in line for tok in required_headers_contain):
            # Must be a tab-separated line
            if '\t' in line:
                header_idx = i
                break

    if header_idx is None:
        return [], []

    headers = [h.strip() for h in lines[header_idx].split('\t')]
    rows = []
    for line in lines[header_idx + 1:]:
        line = line.strip()
        if not line:
            continue
        if line.startswith('Volatility') or line.startswith('Progress'):
            continue
        parts = [p.strip() for p in line.split('\t')]
        if len(parts) >= 2:
            row = {}
            for j, h in enumerate(headers):
                row[h] = parts[j] if j < len(parts) else ''
            rows.append(row)
    return headers, rows


# ── Process List ─────────────────────────────────────────────────────────────

def extract_process_list(image_path):
    print(f"[VOL] Extracting process list from: {os.path.basename(image_path)}")

    raw, err = _run_vol(image_path, 'windows.pslist')
    if err:
        return {"error": f"windows.pslist failed: {err}"}
    if not raw:
        return {"error": "windows.pslist returned no output. Confirm this is a Windows memory image."}

    h = hash_raw_output(raw)
    _, rows = _parse_tsv(raw, ['PID', 'ImageFileName'])

    conn = get_connection()
    c = conn.cursor()
    inserted = 0

    for row in rows:
        try:
            pid_val  = row.get('PID', '0').strip()
            ppid_val = row.get('PPID', '0').strip()
            pid  = int(pid_val)  if pid_val.isdigit()  else 0
            ppid = int(ppid_val) if ppid_val.isdigit() else 0
            name = row.get('ImageFileName', row.get('Name', '')).strip()
            if not name:
                continue
            threads_val = row.get('Threads', '0').strip()
            handles_val = row.get('Handles', '0').strip()

            c.execute('''INSERT INTO memory_processes
                (pid, ppid, process_name, create_time, exit_time,
                 threads, handles, sha256_of_raw_output)
                VALUES (?,?,?,?,?,?,?,?)''',
                (pid, ppid, name,
                 row.get('CreateTime', '').strip(),
                 row.get('ExitTime', '').strip(),
                 int(threads_val) if threads_val.isdigit() else 0,
                 int(handles_val) if handles_val.isdigit() else 0,
                 h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    reported_count = inserted

    print(f"[VOL] Inserted {reported_count} processes")
    return {
        "status": "success", "table": "memory_processes",
        "rows_inserted": reported_count, "sha256": h,
        "schema": {
            "pid": "int", "ppid": "int", "process_name": "str",
            "create_time": "datetime", "exit_time": "datetime",
            "threads": "int", "handles": "int"
        },
        "message": (
            f"{reported_count} processes extracted from memory. "
            "Suspicious indicators: cmd.exe/powershell.exe spawned from unusual parents, "
            "processes with no create_time (injected), or duplicate process names."
        )
    }


# ── Network Connections ───────────────────────────────────────────────────────

def extract_network_connections(image_path):
    print(f"[VOL] Extracting network connections from: {os.path.basename(image_path)}")

    raw, err = _run_vol(image_path, 'windows.netscan', timeout=1200)
    if err:
        return {"error": f"windows.netscan failed: {err}"}
    if not raw:
        return {
            "status": "success", "table": "memory_network",
            "rows_inserted": 0, "sha256": "empty",
            "message": "No network connections found in memory image."
        }

    h = hash_raw_output(raw)
    _, rows = _parse_tsv(raw, ['LocalAddr', 'Proto', 'ForeignAddr'])

    conn = get_connection()
    c = conn.cursor()
    inserted = 0

    for row in rows:
        try:
            local  = row.get('LocalAddr', '').strip()
            foreign = row.get('ForeignAddr', row.get('RemoteAddr', '')).strip()

            # Split addr:port safely
            def split_addr_port(s):
                if ':' in s:
                    idx = s.rfind(':')
                    return s[:idx], s[idx+1:]
                return s, '0'

            la, lp = split_addr_port(local)
            fa, fp = split_addr_port(foreign)

            pid_val = row.get('PID', '0').strip()
            c.execute('''INSERT INTO memory_network
                (pid, process_name, proto, local_addr, local_port,
                 remote_addr, remote_port, state, sha256_of_raw_output)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (int(pid_val) if pid_val.isdigit() else 0,
                 row.get('Owner', row.get('Process', '')).strip(),
                 row.get('Proto', '').strip(),
                 la.strip(), lp.strip(),
                 fa.strip(), fp.strip(),
                 row.get('State', '').strip(),
                 h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    reported_count = inserted

    print(f"[VOL] Inserted {reported_count} network connections")
    return {
        "status": "success", "table": "memory_network",
        "rows_inserted": reported_count, "sha256": h,
        "schema": {
            "pid": "int", "process_name": "str", "proto": "str",
            "local_addr": "str", "local_port": "str",
            "remote_addr": "str", "remote_port": "str", "state": "str"
        },
        "message": (
            f"{reported_count} network connections. "
            "Flag: ESTABLISHED connections from non-browser processes, "
            "connections to high ports (>1024), "
            "processes that should not make network connections."
        )
    }


# ── Command Lines ─────────────────────────────────────────────────────────────

def extract_cmdlines(image_path):
    print(f"[VOL] Extracting command lines from: {os.path.basename(image_path)}")

    raw, err = _run_vol(image_path, 'windows.cmdline')
    if err:
        return {"error": f"windows.cmdline failed: {err}"}
    if not raw:
        return {
            "status": "success", "table": "memory_cmdlines",
            "rows_inserted": 0, "sha256": "empty",
            "message": "No command lines recovered from memory."
        }

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0

    lines = raw.strip().split('\n')
    # cmdline output: PID  Process  Args  (tab separated)
    in_data = False
    parsed_cmdlines_count = 0
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if 'PID' in line and 'Process' in line:
            in_data = True
            continue
        if not in_data:
            continue
        if line.startswith('Volatility') or line.startswith('Progress'):
            continue

        parts = line.split('\t', 2)
        if len(parts) >= 2:
            parsed_cmdlines_count += 1
            try:
                pid_val = parts[0].strip()
                pid = int(pid_val) if pid_val.isdigit() else 0
                process_name = parts[1].strip()
                cmdline = parts[2].strip() if len(parts) > 2 else ''

                c.execute('''INSERT INTO memory_cmdlines
                    (pid, process_name, cmdline, sha256_of_raw_output)
                    VALUES (?,?,?,?)''',
                    (pid, process_name, cmdline, h))
                inserted += 1
            except Exception:
                continue

    conn.commit()
    conn.close()
    reported_count = inserted

    print(f"[VOL] Inserted {reported_count} command lines")
    return {
        "status": "success", "table": "memory_cmdlines",
        "rows_inserted": reported_count, "sha256": h,
        "schema": {"pid": "int", "process_name": "str", "cmdline": "str"},
        "message": (
            f"{reported_count} command lines extracted. "
            "Red flags: Base64-encoded PowerShell (-EncodedCommand), "
            "cmd.exe /c with long argument strings, "
            "LOLBins (certutil, mshta, regsvr32) with unusual arguments."
        )
    }


# ── Malfind (Memory Injection Detection) ─────────────────────────────────────

def extract_malfind(image_path):
    print(f"[VOL] Running malfind (injection detection): {os.path.basename(image_path)}")
    print(f"[VOL] malfind may take 5-10 minutes on large images...")

    raw, err = _run_vol(image_path, 'windows.malfind', timeout=900)
    if err:
        return {"error": f"windows.malfind failed: {err}"}
    if not raw:
        return {
            "status": "success", "table": "memory_injections",
            "rows_inserted": 0, "sha256": "empty",
            "message": "No suspicious memory injections detected by malfind."
        }

    h = hash_raw_output(raw)
    _, rows = _parse_tsv(raw, ['PID', 'Protection', 'Start VPN'])

    conn = get_connection()
    c = conn.cursor()
    inserted = 0

    for row in rows:
        pid_val = row.get('PID', '0').strip()
        try:
            c.execute('''INSERT INTO memory_injections
                (pid, process_name, start_va, end_va,
                 protection, file_output, sha256_of_raw_output)
                VALUES (?,?,?,?,?,?,?)''',
                (int(pid_val) if pid_val.isdigit() else 0,
                 row.get('Process', '').strip(),
                 row.get('Start VPN', '').strip(),
                 row.get('End VPN', '').strip(),
                 row.get('Protection', '').strip(),
                 row.get('File output', '').strip(),
                 h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    reported_count = inserted

    print(f"[VOL] Inserted {reported_count} suspicious memory regions")
    return {
        "status": "success", "table": "memory_injections",
        "rows_inserted": reported_count, "sha256": h,
        "schema": {
            "pid": "int", "process_name": "str",
            "start_va": "str (hex)", "end_va": "str (hex)",
            "protection": "str — PAGE_EXECUTE_READWRITE = shellcode indicator",
            "file_output": "str"
        },
        "message": (
            f"{reported_count} suspicious memory regions flagged. "
            "PAGE_EXECUTE_READWRITE protection = shellcode or reflective DLL injection. "
            "Cross-reference PIDs with memory_processes table."
        )
    }