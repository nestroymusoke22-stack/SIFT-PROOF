import subprocess
import os
import sys
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, hash_raw_output
from tools.native_parsers import native_evtx

KEY_IDS = [4624, 4625, 4648, 4688, 4698, 4720, 4732, 7045, 1102]


def extract_evtx_events(image_path=None, event_ids=None, raw_output=None):
    """
    Extract Windows Event Log records.

    Routing:
      - directory mount    → native python-evtx parser (cross-platform)
      - csv raw_output      → parse supplied EvtxECmd CSV
      - logs dir + evtxecmd → shell out to EvtxECmd
    """
    if event_ids is None:
        event_ids = KEY_IDS
    print(f"[EVTX] Extracting event IDs: {event_ids}")

    # Live mount directory → native parser
    if image_path and os.path.isdir(image_path):
        return native_evtx(image_path, event_ids)

    if raw_output:
        raw = raw_output
    else:
        if not image_path or not os.path.exists(image_path):
            return {
                "status": "error", "table": "evtx_events",
                "rows_inserted": 0, "error": f"Path not found: {image_path}"
            }
        if not shutil.which('evtxecmd'):
            return {
                "status": "error", "table": "evtx_events",
                "rows_inserted": 0,
                "error": "evtxecmd not installed and image is not a mounted "
                         "directory. Mount the volume and pass the path."
            }
        try:
            result = subprocess.run(
                ['evtxecmd', '-d', image_path, '--csv', '/tmp/evtx_out'],
                capture_output=True, text=True, timeout=300
            )
            csv_path = '/tmp/evtx_out.csv'
            if os.path.exists(csv_path):
                with open(csv_path) as f:
                    raw = f.read()
            else:
                raw = result.stdout
        except Exception as e:
            return {
                "status": "error", "table": "evtx_events",
                "rows_inserted": 0, "error": f"EVTX failed: {e}"
            }

    h = hash_raw_output(raw)
    conn = get_connection()
    c = conn.cursor()
    inserted = 0
    lines = raw.strip().split('\n')
    if lines and 'EventId' in lines[0]:
        lines = lines[1:]
        
    for line in lines:
        if not line.strip():
            continue
        parts = line.split(',')
        if len(parts) < 4:
            continue
            
        try:
            eid = int(parts[1].strip().strip('"'))
            if event_ids and eid not in event_ids:
                continue
                
            c.execute(
                '''INSERT INTO evtx_events
                   (event_id, timestamp, computer, username, description,
                    source_tool, sha256_of_raw_output)
                   VALUES (?,?,?,?,?,?,?)''',
                (eid, parts[0].strip().strip('"'),
                 parts[2].strip().strip('"') if len(parts) > 2 else '',
                 parts[3].strip().strip('"') if len(parts) > 3 else '',
                 parts[4].strip().strip('"') if len(parts) > 4 else '',
                 'EvtxECmd', h))
            inserted += 1
        except Exception:
            continue

    conn.commit()
    conn.close()
    
    return {
        "status": "success", "table": "evtx_events",
        "rows_inserted": inserted, "sha256": h,
        "schema": {
            "event_id": "int", "timestamp": "datetime", "computer": "str",
            "username": "str", "description": "str"
        },
        "message": (f"{inserted} events loaded. Key IDs: 4688=process_create, "
                    f"4624=logon, 1102=log_cleared")
    }