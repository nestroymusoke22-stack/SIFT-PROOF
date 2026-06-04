"""
core/database.py — SQLite Evidence Layer

WHY: Raw SIFT tool output is thousands of lines of text.
     Feeding that to an LLM causes context overload and hallucinations.
     This file converts all raw output into SQLite tables BEFORE
     the LLM ever sees it. The LLM gets schema + row counts only.
     It then queries the database using SQL — facts, not guesses.
"""

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
    for t in ['mft_events', 'amcache_entries', 'prefetch_events',
              'evtx_events', 'registry_runkeys', 'confirmed_findings']:
        c.execute(f"DELETE FROM {t}")
    conn.commit()
    conn.close()
    print("[DB] Cleared for new investigation.")


initialize_database()