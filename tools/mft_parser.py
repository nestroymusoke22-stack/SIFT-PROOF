

import subprocess, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output


def extract_mft_timeline(image_path=None, raw_output=None):
    print(f"[MFT] Extracting timeline: {image_path}")

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {"error": f"Image not found: {image_path}"}
        try:
            fls = subprocess.run(
                ['fls', '-r', '-m', '/', '-z', 'UTC', image_path],
                capture_output=True, text=True, timeout=300
            )
            mac = subprocess.run(
                ['mactime', '-b', '-', '-z', 'UTC'],
                input=fls.stdout, capture_output=True, text=True, timeout=120
            )
            raw = mac.stdout
        except FileNotFoundError:
            return {"error": "fls/mactime not found. Run inside SIFT Workstation VM."}
        except subprocess.TimeoutExpired:
            return {"error": "Timeout. Image may be too large."}

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0

    for line in raw.split('\n'):
        line = line.strip()
        if not line or line.startswith('Date'):
            continue
        parts = line.split(',')
        if len(parts) < 10:
            continue
        try:
            filename = os.path.basename(parts[9].strip())
            c.execute('''INSERT INTO mft_events
                (filename, full_path, modified_at, created_at, accessed_at,
                 file_size, action, sha256_of_raw_output)
                VALUES (?,?,?,?,?,?,?,?)''',
                (filename, parts[9].strip(), parts[0].strip(), parts[0].strip(),
                 parts[0].strip(),
                 int(parts[1].strip()) if parts[1].strip().isdigit() else 0,
                 parts[2].strip(), h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    print(f"[MFT] Inserted {inserted} events")
    return {
        "status": "success", "table": "mft_events",
        "rows_inserted": inserted, "sha256": h,
        "schema": {"filename": "str", "full_path": "str", "created_at": "datetime",
                   "modified_at": "datetime", "file_size": "int", "action": "str"},
        "message": f"{inserted} file events loaded. Query using submit_claim on 'mft_events'."
    }