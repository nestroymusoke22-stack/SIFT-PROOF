import subprocess
import os
import sys
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
from tools.native_parsers import native_mft


def extract_mft_timeline(image_path=None, raw_output=None):
    """
    Build a file-system timeline.

    Routing:
      - directory mount  → native os.walk timeline (cross-platform)
      - image file + fls → Sleuth Kit fls/mactime pipe-delimited output
    """
    print(f"[MFT] Extracting timeline: {image_path}")

    # Live mount directory → native walker
    if image_path and os.path.isdir(image_path):
        return native_mft(image_path)

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {
                "status": "error", "table": "mft_events",
                "rows_inserted": 0, "error": f"Path not found: {image_path}"
            }
        if not shutil.which('fls'):
            return {
                "status": "error", "table": "mft_events",
                "rows_inserted": 0,
                "error": "fls (Sleuth Kit) not installed and image is not a "
                         "mounted directory. Mount the image and pass the path."
            }
        try:
            fls = subprocess.run(
                ['fls', '-r', '-m', '/', '-z', 'UTC', image_path],
                capture_output=True, text=True, timeout=300
            )
            raw = fls.stdout
        except subprocess.TimeoutExpired:
            return {
                "status": "error", "table": "mft_events",
                "rows_inserted": 0, "error": "fls timed out (image too large)."
            }
        except Exception as e:
            return {
                "status": "error", "table": "mft_events",
                "rows_inserted": 0, "error": f"fls failed: {e}"
            }

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0
    
    for line in raw.split('\n'):
        line = line.strip()
        if not line or line.startswith('Date') or line.startswith('MD5'):
            continue
            
        parts = line.split('|')
        if len(parts) < 11:
            continue
            
        try:
            full_path = parts[1].strip()
            filename = os.path.basename(full_path)
            action_flags = parts[0].strip()
            modified_time = parts[7].strip()
            accessed_time = parts[8].strip()
            created_time = parts[9].strip()
            file_size = int(parts[6].strip()) if parts[6].strip().isdigit() else 0
            
            c.execute(
                '''INSERT INTO mft_events
                   (filename, full_path, modified_at, created_at, accessed_at,
                    file_size, action, source_tool, sha256_of_raw_output)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (filename, full_path, modified_time, created_time, accessed_time,
                 file_size, action_flags, 'fls/mactime', h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    
    print(f"[MFT] Inserted {inserted} events")
    return {
        "status": "success", "table": "mft_events",
        "rows_inserted": inserted, "sha256": h,
        "schema": {
            "filename": "str", "full_path": "str", "created_at": "datetime",
            "modified_at": "datetime", "file_size": "int", "action": "str"
        },
        "message": f"{inserted} file events loaded. Query using submit_claim on 'mft_events'."
    }