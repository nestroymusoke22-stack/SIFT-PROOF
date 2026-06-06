import subprocess
import os
import sys
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
from tools.native_parsers import native_registry_run


def extract_registry_run(image_path=None, raw_output=None):
    """
    Extract registry Run/RunOnce persistence keys.

    Routing:
      - directory mount        → native python-registry parser (cross-platform)
      - regripper raw_output    → parse the supplied text
      - hive file + regripper   → shell out to regripper -p run
    """
    print(f"[REGISTRY] Extracting run keys: {image_path}")

    # Live mount directory → native parser
    if image_path and os.path.isdir(image_path):
        return native_registry_run(image_path)

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {
                "status": "error", "table": "registry_runkeys",
                "rows_inserted": 0, "error": f"Path not found: {image_path}"
            }
        if not shutil.which('regripper'):
            return {
                "status": "error", "table": "registry_runkeys",
                "rows_inserted": 0,
                "error": "regripper not installed and image is not a mounted "
                         "directory. Pass a mounted path to use the native parser."
            }
        try:
            # NOTE: the correct standard plugin is 'run' (not 'runkeys').
            result = subprocess.run(
                ['regripper', '-r', image_path, '-p', 'run'],
                capture_output=True, text=True, timeout=120
            )
            raw = result.stdout
        except Exception as e:
            return {
                "status": "error", "table": "registry_runkeys",
                "rows_inserted": 0, "error": f"Registry extraction failed: {e}"
            }

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0
    current_hive = ''
    current_key = ''
    
    for line in raw.split('\n'):
        line = line.strip()
        if line.startswith(('HKLM', 'HKCU', 'HKU')):
            current_hive = line.split('\\')[0]
            current_key = line
        elif ' -> ' in line:
            parts = line.split(' -> ', 1)
            if len(parts) == 2:
                try:
                    c.execute(
                        '''INSERT INTO registry_runkeys
                           (hive, key_path, value_name, value_data,
                            source_tool, sha256_of_raw_output)
                           VALUES (?,?,?,?,?,?)''',
                        (current_hive, current_key,
                         parts[0].strip(), parts[1].strip(), 'regripper', h))
                    inserted += 1
                except Exception:
                    continue

    conn.commit()
    conn.close()
    
    return {
        "status": "success", "table": "registry_runkeys",
        "rows_inserted": inserted, "sha256": h,
        "schema": {
            "hive": "str", "key_path": "str",
            "value_name": "str", "value_data": "str (usually a file path)"
        },
        "message": f"{inserted} registry persistence entries loaded."
    }