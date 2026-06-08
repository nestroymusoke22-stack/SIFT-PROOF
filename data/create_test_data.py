
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.database import get_connection, initialize_database, clear_database

# Fake SHA256 — in real runs this is the actual hash of raw tool output
HASH = "e3b0c44298fc1c149afbf4c8996fb924" + "27ae41e4649b934ca495991b7852b855"

def create_test_dataset():
    initialize_database()
    clear_database()

    conn = get_connection()
    c = conn.cursor()

    # ──────────────────────────────────────────────────────────────────────────
    # 1. MFT & TIMELINE EVENTS
    # ──────────────────────────────────────────────────────────────────────────
    # Features Proven: 
    #   - File Deletion vs Execution desync
    #   - NTFS Timestomping ($SI vs $FN mismatch attribute anomalies)
    c.executemany(
        '''INSERT INTO mft_events 
        (filename, full_path, modified_at, created_at, accessed_at, 
         file_size, action, sha256_of_raw_output) VALUES (?,?,?,?,?,?,?,?)''',
        [
            # EDGE CASE A: File deleted at 03:12, but prefetch says it ran at 03:17
            ('evil.exe', 'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe',
             '2024-03-14 03:10:00', '2024-03-14 03:09:55',
             '2024-03-14 03:10:00', 524288, 'create', HASH),
            
            ('evil.exe', 'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe',
             '2024-03-14 03:12:00', '2024-03-14 03:09:55',
             '2024-03-14 03:12:00', 524288, 'delete', HASH),

            # EDGE CASE B: NTFS Timestomping. 
            # Standard info says created 2018 (fake), but filename info attribute shows 2026!
            # (Represented here via structural markers for the agent parser rule)
            ('svchost.exe', 'C:\\Users\\NESTORY\\AppData\\Local\\Temp\\svchost.exe',
             '2018-05-12 11:00:00', '2018-05-12 11:00:00', # $STANDARD_INFORMATION
             '2026-06-06 18:00:00', 1048576, 'create_timestomped_anomaly', HASH), 

            ('mimikatz.exe', 'C:\\Temp\\mimikatz.exe',
             '2024-03-14 03:11:00', '2024-03-14 03:11:00',
             '2024-03-14 03:11:00', 1245184, 'create', HASH),
        ]
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 2. PREFETCH EXECUTION HISTORY
    # ──────────────────────────────────────────────────────────────────────────
    # Features Proven: Evidence of execution after deletion & LOLBin monitoring
    c.executemany(
        '''INSERT INTO prefetch_events 
        (executable_name, last_run_time, run_count, sha256_of_raw_output) 
        VALUES (?,?,?,?)''',
        [
            ('EVIL.EXE-AB12CD34.pf', '2024-03-14 03:17:22', 3, HASH), # 5 mins AFTER delete
            ('MIMIKATZ.EXE-1234ABCD.pf', '2024-03-14 03:11:30', 1, HASH),
            
            # EDGE CASE C: LOLBin (Certutil downloading payloads over the network)
            ('CERTUTIL.EXE-99AA88BB.pf', '2024-03-14 03:08:12', 14, HASH),
        ]
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 3. AMCACHE / COMPONENT REGISTRATION
    # ──────────────────────────────────────────────────────────────────────────
    c.executemany(
        '''INSERT INTO amcache_entries 
        (program_name, program_path, sha256_hash, first_run_time, sha256_of_raw_output) 
        VALUES (?,?,?,?,?)''',
        [
            ('evil.exe', 'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe', 'deadbeef'*8, '2024-03-14 03:10:00', HASH),
            ('mimikatz.exe', 'C:\\Temp\\mimikatz.exe', 'cafebabe'*8, '2024-03-14 03:11:00', HASH),
        ]
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 4. MEMORY / LIVE RUNTIME SYSTEM PROCESSES
    # ──────────────────────────────────────────────────────────────────────────
    # Features Proven: Rogue Service Masquerading & Parent-PID hijacking footprints
    # Ensure memory tracking tables exist inside your schema integration
    try:
        c.executemany(
            '''INSERT INTO memory_processes 
            (pid, ppid, process_name, create_time, exit_time, threads, handles) 
            VALUES (?,?,?,?,?,?,?)''',
            [
                # EDGE CASE D: Rogue svchost.exe spawned out of Temp folder by an untrusted parent
                (8824, 9999, 'svchost.exe', '2024-03-14 03:10:05', 'N/A', 266, 1205),
                (9999, 1232, 'cmd.exe', '2024-03-14 03:09:45', 'N/A', 1, 45),
            ]
        )
    except sqlite3.OperationalError:
        # Dynamic fallback if memory tables are mapped slightly differently in schema
        pass

    # ──────────────────────────────────────────────────────────────────────────
    # 5. NETWORKING / SOCKET FOOTPRINTS
    # ──────────────────────────────────────────────────────────────────────────
    # Features Proven: Correlating hijacked processes to known C2 threat intelligence addresses
    try:
        c.executemany(
            '''INSERT INTO memory_network 
            (pid, process_name, proto, local_addr, local_port, remote_addr, remote_port, state) 
            VALUES (?,?,?,?,?,?,?,?)''',
            [
                # Connects the rogue svchost.exe directly to an off-grid threat vector
                (8824, 'svchost.exe', 'TCPv4', '192.168.1.5', '49788', '185.220.101.1', '443', 'ESTABLISHED'),
            ]
        )
    except sqlite3.OperationalError:
        pass

    # ──────────────────────────────────────────────────────────────────────────
    # 6. PERSISTENCE MECHANISMS (REGISTRY RUN KEYS)
    # ──────────────────────────────────────────────────────────────────────────
    c.executemany(
        '''INSERT INTO registry_runkeys 
        (hive, key_path, value_name, value_data, sha256_of_raw_output) 
        VALUES (?,?,?,?,?)''',
        [
            ('HKCU', 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 
             'WindowsUpdater', 'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe', HASH),
            ('HKLM', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 
             'SecurityHealth', 'C:\\Windows\\System32\\SecurityHealthSystray.exe', HASH),
        ]
    )

    # ──────────────────────────────────────────────────────────────────────────
    # 7. EVENT LOGS
    # ──────────────────────────────────────────────────────────────────────────
    # Features Proven: Insider threats, execution mapping, and evasion attempts
    c.executemany(
        '''INSERT INTO evtx_events 
        (event_id, timestamp, computer, username, description, sha256_of_raw_output) 
        VALUES (?,?,?,?,?,?)''',
        [
            (4688, '2024-03-14 03:10:45', 'WORKSTATION-01', 'NESTORY', 
             'Process created: C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe', HASH),
            (4688, '2024-03-14 03:11:00', 'WORKSTATION-01', 'NESTORY', 
             'Process created: C:\\Temp\\mimikatz.exe', HASH),
            (4624, '2024-03-14 02:55:00', 'WORKSTATION-01', 'NESTORY', 
             'Successful logon via physical console', HASH),
            
            # EDGE CASE E: Anti-Forensic Evasion (Log clearance signature)
            (1102, '2024-03-14 03:09:00', 'WORKSTATION-01', 'NESTORY', 
             'The security audit log was explicitly cleared by Administrator privileges', HASH),
        ]
    )

    conn.commit()
    conn.close()

    print("=" * 65)
    print("🚀 SIFT-PROOF ADVANCED TESTING REGIME INITIALIZED SUCCESSFUL")
    print("=" * 65)
    print(" [Case 1] Temporal Contradiction: evil.exe deleted 03:12 -> ran 03:17")
    print(" [Case 2] NTFS Timestomping: svchost.exe contains modified $SI attributes")
    print(" [Case 3] Process/C2 Blending: PID 8824 (svchost) talking to Tor Node IP")
    print(" [Case 4] Defensive Evasion: Event ID 1102 Log Wipe detected")
    print(" [Case 5] LOLBin Execution: Certutil network fetching recorded")
    print("=" * 65)
    print("Run your live agent investigation loop now to verify discovery claims.")

if __name__ == "__main__":
    create_test_dataset()