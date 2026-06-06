import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from core.database import get_connection, initialize_database


def add_memory_tables():
    initialize_database()   # ensure base tables exist first
    conn = get_connection()
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS memory_processes (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        pid             INTEGER,
        ppid            INTEGER,
        process_name    TEXT,
        create_time     TEXT,
        exit_time       TEXT,
        threads         INTEGER DEFAULT 0,
        handles         INTEGER DEFAULT 0,
        sha256_of_raw_output TEXT,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS memory_network (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        pid             INTEGER,
        process_name    TEXT,
        proto           TEXT,
        local_addr      TEXT,
        local_port      TEXT,
        remote_addr     TEXT,
        remote_port     TEXT,
        state           TEXT,
        sha256_of_raw_output TEXT,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS memory_cmdlines (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        pid             INTEGER,
        process_name    TEXT,
        cmdline         TEXT,
        sha256_of_raw_output TEXT,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS memory_injections (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        pid             INTEGER,
        process_name    TEXT,
        start_va        TEXT,
        end_va          TEXT,
        protection      TEXT,
        file_output     TEXT,
        sha256_of_raw_output TEXT,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()
    conn.close()
    print("[DB] Memory tables created: memory_processes, memory_network, memory_cmdlines, memory_injections")


if __name__ == "__main__":
    add_memory_tables()
    print("[DB] Memory module ready.")
