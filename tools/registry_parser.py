

import subprocess, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output


def extract_registry_runkeys(image_path=None, raw_output=None):
    print(f"[REGISTRY] Extracting run keys: {image_path}")

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {"error": f"Image not found: {image_path}"}
        try:
            result = subprocess.run(
                ['regripper', '-r', image_path, '-p', 'run'],
                capture_output=True, text=True, timeout=120
            )
            raw = result.stdout
        except Exception as e:
            return {"error": f"Registry extraction failed: {e}"}

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
                c.execute('''INSERT INTO registry_runkeys
                    (hive, key_path, value_name, value_data, sha256_of_raw_output)
                    VALUES (?,?,?,?,?)''',
                    (current_hive, current_key,
                     parts[0].strip(), parts[1].strip(), h))
                inserted += 1

    conn.commit()
    conn.close()
    return {
        "status": "success", "table": "registry_runkeys",
        "rows_inserted": inserted, "sha256": h,
        "schema": {"hive": "str", "key_path": "str",
                   "value_name": "str", "value_data": "str (usually a file path)"},
        "message": f"{inserted} registry persistence entries loaded."
    }