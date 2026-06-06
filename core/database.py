import sqlite3
import hashlib
import os

# Evidence database lives in the data/ folder
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'evidence.db')


def get_connection():
    """Central database connection. Returns dict-style rows for easy use."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Creates all tables. Safe to call multiple times — uses IF NOT EXISTS."""
    conn = get_connection()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS mft_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT, full_path TEXT,
        created_at TEXT, modified_at TEXT, accessed_at TEXT,
        file_size INTEGER, action TEXT,
        source_tool TEXT DEFAULT 'fls/mactime',
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS amcache_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT, program_path TEXT,
        sha256_hash TEXT, first_run_time TEXT, last_run_time TEXT,
        source_tool TEXT DEFAULT 'AppCompatCacheParser',
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS prefetch_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        executable_name TEXT, run_count INTEGER, last_run_time TEXT,
        volume_path TEXT,
        source_tool TEXT DEFAULT 'PECmd',
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS evtx_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER, timestamp TEXT, computer TEXT,
        username TEXT, description TEXT,
        source_tool TEXT DEFAULT 'EvtxECmd',
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS registry_runkeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hive TEXT, key_path TEXT, value_name TEXT, value_data TEXT,
        last_modified TEXT,
        source_tool TEXT DEFAULT 'RegRipper',
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS confirmed_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT UNIQUE,
        claim TEXT, evidence_table TEXT,
        sql_filter TEXT, sql_executed TEXT,
        rows_matched INTEGER, assertion_result TEXT,
        confidence_tier TEXT, temporal_check TEXT,
        mitre_technique TEXT, sha256_of_evidence TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # ── Memory-analysis tables (Volatility3) ──────────────────────────────────
    c.execute('''CREATE TABLE IF NOT EXISTS memory_processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER, ppid INTEGER, process_name TEXT,
        create_time TEXT, exit_time TEXT,
        threads INTEGER DEFAULT 0, handles INTEGER DEFAULT 0,
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS memory_network (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER, process_name TEXT, proto TEXT,
        local_addr TEXT, local_port TEXT,
        remote_addr TEXT, remote_port TEXT, state TEXT,
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS memory_cmdlines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER, process_name TEXT, cmdline TEXT,
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS memory_injections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pid INTEGER, process_name TEXT,
        start_va TEXT, end_va TEXT,
        protection TEXT, file_output TEXT,
        sha256_of_raw_output TEXT,
        inserted_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # ── Defensive indexes on heavily-filtered columns (query speed) ───────────
    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_mft_filename ON mft_events(filename)",
        "CREATE INDEX IF NOT EXISTS idx_mft_full_path ON mft_events(full_path)",
        "CREATE INDEX IF NOT EXISTS idx_mft_action ON mft_events(action)",
        "CREATE INDEX IF NOT EXISTS idx_amcache_name ON amcache_entries(program_name)",
        "CREATE INDEX IF NOT EXISTS idx_prefetch_name ON prefetch_events(executable_name)",
        "CREATE INDEX IF NOT EXISTS idx_evtx_event_id ON evtx_events(event_id)",
        "CREATE INDEX IF NOT EXISTS idx_reg_key_path ON registry_runkeys(key_path)",
        "CREATE INDEX IF NOT EXISTS idx_reg_value_data ON registry_runkeys(value_data)",
        "CREATE INDEX IF NOT EXISTS idx_memproc_name ON memory_processes(process_name)",
        "CREATE INDEX IF NOT EXISTS idx_memcmd_name ON memory_cmdlines(process_name)",
        "CREATE INDEX IF NOT EXISTS idx_memnet_remote ON memory_network(remote_addr)",
    ):
        c.execute(stmt)

    conn.commit()
    conn.close()
    print("[DB] All tables initialized.")


def hash_raw_output(raw_text):
    """SHA256 of raw tool output — the chain of custody proof."""
    return hashlib.sha256(raw_text.encode('utf-8', errors='replace')).hexdigest()


def execute_safe_query(sql, params=None):
    """
    Only SELECT queries allowed. Anything else raises ValueError.
    This is an architectural guardrail — not a prompt instruction.
    """
    if not sql.strip().upper().startswith('SELECT'):
        raise ValueError(
            f"SECURITY VIOLATION: Only SELECT is permitted. "
            f"Got: {sql.strip()[:30]}..."
        )
    conn = get_connection()
    c = conn.cursor()
    c.execute(sql, params or [])
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def clear_database():
    """Wipes all tables for a fresh investigation."""
    conn = get_connection()
    c = conn.cursor()
    tables = [
        'mft_events', 'amcache_entries', 'prefetch_events',
        'evtx_events', 'registry_runkeys', 'confirmed_findings',
        'memory_processes', 'memory_network',
        'memory_cmdlines', 'memory_injections'
    ]
    for t in tables:
        c.execute(f"DELETE FROM {t}")
    conn.commit()
    conn.close()
    print("[DB] Cleared for new investigation.")


initialize_database()