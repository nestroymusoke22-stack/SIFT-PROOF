import subprocess
import os
import sys
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
from tools.native_parsers import native_amcache


def extract_amcache(image_path=None, raw_output=None):
    """
    Extract AmCache execution records.

    Routing:
      - directory mount       → native python-registry Amcache.hve parser
      - regripper raw_output   → parse supplied text
      - hive file + regripper  → shell out to regripper -p amcache
    """
    print(f"[AMCACHE] Extracting: {image_path}")

    # Live mount directory → native parser
    if image_path and os.path.isdir(image_path):
        return native_amcache(image_path)

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {
                "status": "error", "table": "amcache_entries",
                "rows_inserted": 0, "error": f"Path not found: {image_path}"
            }
        if not shutil.which('regripper'):
            return {
                "status": "error", "table": "amcache_entries",
                "rows_inserted": 0,
                "error": "regripper not installed and image is not a mounted "
                         "directory. Mount the volume and pass the path."
            }
        try:
            result = subprocess.run(
                ['regripper', '-r', image_path, '-p', 'amcache'],
                capture_output=True, text=True, timeout=120
            )
            raw = result.stdout
        except Exception as e:
            return {
                "status": "error", "table": "amcache_entries",
                "rows_inserted": 0, "error": f"AmCache extraction failed: {e}"
            }

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0
    entry = {}

    def _flush(e):
        nonlocal inserted
        if not e.get('name'):
            return
        try:
            c.execute(
                '''INSERT INTO amcache_entries
                   (program_name, program_path, sha256_hash, first_run_time,
                    source_tool, sha256_of_raw_output)
                   VALUES (?,?,?,?,?,?)''',
                (e.get('name', ''), e.get('path', ''),
                 e.get('sha256', ''), e.get('run', ''), 'regripper', h))
            inserted += 1
        except Exception:
            pass

    for line in raw.split('\n'):
        line = line.strip()
        if line.startswith('AppName:'):
            _flush(entry)
            entry = {'name': line.split(':', 1)[1].strip()}
        elif line.startswith('AppPath:'):
            entry['path'] = line.split(':', 1)[1].strip()
        elif line.startswith('SHA256:'):
            entry['sha256'] = line.split(':', 1)[1].strip()
        elif 'First Run' in line or 'LastModified' in line:
            entry['run'] = line.split(':', 1)[1].strip() if ':' in line else ''
            
    _flush(entry)
    conn.commit()
    conn.close()
    
    return {
        "status": "success", "table": "amcache_entries",
        "rows_inserted": inserted, "sha256": h,
        "schema": {
            "program_name": "str", "program_path": "str",
            "sha256_hash": "str (SHA256 of binary)", "first_run_time": "datetime"
        },
        "message": f"{inserted} execution records loaded. SHA256 hashes can identify malware."
    }