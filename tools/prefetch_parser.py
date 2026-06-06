import subprocess
import os
import sys
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
from tools.native_parsers import native_prefetch


def extract_prefetch(image_path=None, raw_output=None):
    """
    Extract Windows Prefetch execution evidence.

    Routing:
      - directory mount   → native .pf parser (cross-platform)
      - csv raw_output     → parse supplied PECmd CSV
      - prefetch dir + pecmd → shell out to PECmd
    """
    print(f"[PREFETCH] Extracting: {image_path}")

    # Live mount directory → native parser
    if image_path and os.path.isdir(image_path):
        return native_prefetch(image_path)

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {
                "status": "error", "table": "prefetch_events",
                "rows_inserted": 0, "error": f"Path not found: {image_path}"
            }
        if not shutil.which('pecmd'):
            return {
                "status": "error", "table": "prefetch_events",
                "rows_inserted": 0,
                "error": "pecmd not installed and image is not a mounted "
                         "directory. Mount the volume and pass the path."
            }
        try:
            result = subprocess.run(
                ['pecmd', '-d', image_path, '--csv', '/tmp/pf_out'],
                capture_output=True, text=True, timeout=120
            )
            csv_path = '/tmp/pf_out.csv'
            if os.path.exists(csv_path):
                with open(csv_path) as f:
                    raw = f.read()
            else:
                raw = result.stdout
        except Exception as e:
            return {
                "status": "error", "table": "prefetch_events",
                "rows_inserted": 0, "error": f"Prefetch failed: {e}"
            }

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0
    lines = raw.strip().split('\n')
    if lines and ('SourceFilename' in lines[0] or 'ExecutableName' in lines[0]):
        lines = lines[1:]
        
    for line in lines:
        if not line.strip():
            continue
        parts = line.split(',')
        if len(parts) < 3:
            continue
            
        try:
            c.execute(
                '''INSERT INTO prefetch_events
                   (executable_name, last_run_time, run_count, source_tool,
                    sha256_of_raw_output)
                   VALUES (?,?,?,?,?)''',
                (parts[0].strip().strip('"'),
                 parts[2].strip().strip('"') if len(parts) > 2 else '',
                 int(parts[3].strip()) if len(parts) > 3 and parts[3].strip().isdigit() else 0,
                 'PECmd', h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    
    return {
        "status": "success", "table": "prefetch_events",
        "rows_inserted": inserted, "sha256": h,
        "schema": {
            "executable_name": "str (includes .pf hash suffix)",
            "last_run_time": "datetime", "run_count": "int"
        },
        "message": f"{inserted} prefetch records loaded. Proves execution even after deletion."
    }