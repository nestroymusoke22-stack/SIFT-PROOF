

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

    # MFT events — note evil.exe is DELETED at 03:12
    c.executemany(
        '''INSERT INTO mft_events
        (filename, full_path, modified_at, created_at, accessed_at,
         file_size, action, sha256_of_raw_output) VALUES (?,?,?,?,?,?,?,?)''',
        [
            ('evil.exe',
             'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe',
             '2024-03-14 03:10:00', '2024-03-14 03:09:55',
             '2024-03-14 03:10:00', 524288, 'create', HASH),

            # THIS IS THE TEMPORAL CONTRADICTION:
            # evil.exe deleted at 03:12, but prefetch says it ran at 03:17
            ('evil.exe',
             'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe',
             '2024-03-14 03:12:00', '2024-03-14 03:09:55',
             '2024-03-14 03:12:00', 524288, 'delete', HASH),

            ('mimikatz.exe', 'C:\\Temp\\mimikatz.exe',
             '2024-03-14 03:11:00', '2024-03-14 03:11:00',
             '2024-03-14 03:11:00', 1245184, 'create', HASH),

            ('notepad.exe', 'C:\\Windows\\System32\\notepad.exe',
             '2024-01-15 10:00:00', '2019-03-19 04:52:00',
             '2024-03-14 03:05:00', 201728, 'access', HASH),
        ]
    )

    # Prefetch — evil.exe at 03:17 (AFTER deletion at 03:12 = IMPOSSIBLE)
    c.executemany(
        '''INSERT INTO prefetch_events
        (executable_name, last_run_time, run_count, sha256_of_raw_output)
        VALUES (?,?,?,?)''',
        [
            ('EVIL.EXE-AB12CD34.pf', '2024-03-14 03:17:22', 3, HASH),
            ('MIMIKATZ.EXE-1234ABCD.pf', '2024-03-14 03:11:30', 1, HASH),
            ('NOTEPAD.EXE-87654321.pf', '2024-03-14 03:05:00', 47, HASH),
            ('CMD.EXE-11223344.pf', '2024-03-14 03:10:45', 8, HASH),
        ]
    )

    # AmCache
    c.executemany(
        '''INSERT INTO amcache_entries
        (program_name, program_path, sha256_hash, first_run_time, sha256_of_raw_output)
        VALUES (?,?,?,?,?)''',
        [
            ('evil.exe', 'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe',
             'deadbeef' * 8, '2024-03-14 03:10:00', HASH),
            ('mimikatz.exe', 'C:\\Temp\\mimikatz.exe',
             'cafebabe' * 8, '2024-03-14 03:11:00', HASH),
        ]
    )

    # Registry run key — persistence mechanism
    c.executemany(
        '''INSERT INTO registry_runkeys
        (hive, key_path, value_name, value_data, sha256_of_raw_output)
        VALUES (?,?,?,?,?)''',
        [
            ('HKCU',
             'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
             'WindowsUpdater',
             'C:\\Users\\NESTORY\\AppData\\Roaming\\evil.exe',
             HASH),
            ('HKLM',
             'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
             'SecurityHealth',
             'C:\\Windows\\System32\\SecurityHealthSystray.exe',
             HASH),
        ]
    )

    # Event logs
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
             'Successful logon', HASH),
            (1102, '2024-03-14 03:09:00', 'WORKSTATION-01', 'NESTORY',
             'The audit log was cleared', HASH),
        ]
    )

    conn.commit()
    conn.close()

    print("✅ Test dataset created:")
    print("   evil.exe — TEMPORAL CONTRADICTION (deleted 03:12, prefetch 03:17)")
    print("   mimikatz.exe — credential dumping tool")
    print("   Registry persistence: HKCU\\Run\\WindowsUpdater → evil.exe")
    print("   Event 1102: Audit log cleared (attacker covering tracks)")
    print()
    print("Run: python3 replay.py --all")


if __name__ == "__main__":
    create_test_dataset()