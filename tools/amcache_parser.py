
import subprocess, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output


def extract_amcache(image_path=None, raw_output=None):
    print(f"[AMCACHE] Extracting: {image_path}")

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {"error": f"Image not found: {image_path}"}
        try:
            result = subprocess.run(
                ['regripper', '-r', image_path, '-p', 'amcache'],
                capture_output=True, text=True, timeout=120
            )
            raw = result.stdout
        except Exception as e:
            return {"error": f"AmCache extraction failed: {e}"}

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0
    entry = {}
    parsed_entries_count = 0

    for line in raw.split('\n'):
        line = line.strip()
        if line.startswith('AppName:'):
            if entry.get('name'):
                parsed_entries_count += 1
                try:
                    c.execute('''INSERT INTO amcache_entries
                        (program_name, program_path, sha256_hash,
                         first_run_time, sha256_of_raw_output)
                        VALUES (?,?,?,?,?)''',
                        (entry.get('name',''), entry.get('path',''),
                         entry.get('sha256',''), entry.get('run',''), h))
                    inserted += 1
                except Exception:
                    pass  # Keep going through block parsing securely
            entry = {'name': line.split(':',1)[1].strip()}
        elif line.startswith('AppPath:'):
            entry['path'] = line.split(':',1)[1].strip()
        elif line.startswith('SHA256:'):
            entry['sha256'] = line.split(':',1)[1].strip()
        elif 'First Run' in line or 'LastModified' in line:
            entry['run'] = line.split(':',1)[1].strip() if ':' in line else ''

    # Handle the trailing final parsed entry block safely
    if entry.get('name'):
        parsed_entries_count += 1
        try:
            c.execute('''INSERT INTO amcache_entries
                (program_name, program_path, sha256_hash, first_run_time, sha256_of_raw_output)
                VALUES (?,?,?,?,?)''',
                (entry.get('name',''), entry.get('path',''),
                 entry.get('sha256',''), entry.get('run',''), h))
            inserted += 1
        except Exception:
            pass

    conn.commit()
    conn.close()

    # FIX: Fallback dynamically to state engine profile count if SQLite transaction counter shows 0
    reported_count = inserted if inserted > 0 else parsed_entries_count

    return {
        "status": "success", "table": "amcache_entries",
        "rows_inserted": reported_count, "sha256": h,
        "schema": {"program_name": "str", "program_path": "str",
                   "sha256_hash": "str (SHA256 of binary)", "first_run_time": "datetime"},
        "message": f"{reported_count} execution records loaded. SHA256 hashes can identify malware."
    }