"""
ArchiveManager: snapshot SQLite evidence DB, create case_{n} archive, index archive in DB.
Provides atomic case numbering and safe snapshotting.
"""

import os
import sqlite3
import json
import tarfile
import tempfile
import shutil
import hashlib
import time
from datetime import datetime
from contextlib import contextmanager

DEFAULT_RETENTION = 10  # configurable elsewhere

class ArchiveError(Exception):
    pass

class ArchiveManager:
    def __init__(self, db_path, base_cases_dir, encrypt_fn=None, logger=None):
        self.db_path = db_path
        self.base_cases_dir = base_cases_dir
        os.makedirs(self.base_cases_dir, exist_ok=True)
        self.encrypt_fn = encrypt_fn  # optional callback to encrypt archive bytes or file path
        self.logger = logger or (lambda *a, **k: None)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            # enable WAL for better concurrency
            conn.execute("PRAGMA journal_mode=WAL;")
            yield conn
        finally:
            conn.close()

    def _sha256_file(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _next_case_number(self, conn):
        # Use an immediate transaction to avoid race conditions across processes
        conn.execute("BEGIN IMMEDIATE;")
        cur = conn.execute("SELECT MAX(case_number) FROM archival_index")
        r = cur.fetchone()[0]
        next_num = int(r or 0) + 1
        # we'll insert after archive creation; keep transaction open if needed
        return next_num

    def _insert_archive_index(self, conn, case_number, archive_path, summary):
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO archival_index (case_number, archive_path, summary, created_at) VALUES (?, ?, ?, ?)",
            (case_number, archive_path, json.dumps(summary), now)
        )
        conn.commit()

    def archive_investigation(self, investigation_id, summary_dict=None, cleanup_temp=True):
        summary_dict = summary_dict or {}
        # create temp workspace
        tmpdir = tempfile.mkdtemp(prefix="siftproof-archive-")
        try:
            # Determine case number (use DB transaction)
            with self._connect() as conn:
                case_number = self._next_case_number(conn)

            case_dir_name = f"case_{case_number:04d}"
            case_dir = os.path.join(self.base_cases_dir, case_dir_name)
            os.makedirs(case_dir, exist_ok=True)

            # snapshot DB using sqlite online backup to a file inside tempdir
            snapshot_path = os.path.join(tmpdir, "evidence_snapshot.db")
            with sqlite3.connect(self.db_path) as src, sqlite3.connect(snapshot_path) as dst:
                src.backup(dst, pages=0, progress=None)
            self.logger("DB snapshot created", snapshot_path=snapshot_path)

            # optionally export other artifacts or reasoning logs by querying DB
            # small helper: dump investigation metadata & state to JSON
            with sqlite3.connect(snapshot_path) as snap:
                snap.row_factory = sqlite3.Row
                cur = snap.cursor()
                cur.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
                inv = cur.fetchone()
                inv_json = dict(inv) if inv else {}
                with open(os.path.join(tmpdir, "investigation_metadata.json"), "w") as f:
                    json.dump(inv_json, f, indent=2)

                # export reasoning_logs for the investigation
                cur.execute("SELECT id, prompt, model_used, response, tokens_used, created_at FROM reasoning_logs WHERE investigation_id = ? ORDER BY created_at ASC", (investigation_id,))
                logs = [dict(r) for r in cur.fetchall()]
                with open(os.path.join(tmpdir, "reasoning_logs.json"), "w") as f:
                    json.dump(logs, f, indent=2)

            # copy snapshot and JSON into case_dir
            shutil.copy(snapshot_path, os.path.join(case_dir, "evidence.db"))
            shutil.copy(os.path.join(tmpdir, "investigation_metadata.json"), os.path.join(case_dir, "investigation_metadata.json"))
            shutil.copy(os.path.join(tmpdir, "reasoning_logs.json"), os.path.join(case_dir, "reasoning_logs.json"))

            # write summary
            summary_path = os.path.join(case_dir, "summary.json")
            summary_dict.update({
                "investigation_id": investigation_id,
                "case_number": case_number,
                "archived_at": datetime.utcnow().isoformat() + "Z"
            })
            with open(summary_path, "w") as f:
                json.dump(summary_dict, f, indent=2)

            # create archive
            archive_filename = f"{case_dir_name}.tar.gz"
            archive_path = os.path.join(self.base_cases_dir, archive_filename)
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(case_dir, arcname=case_dir_name)

            # optional encryption step
            if self.encrypt_fn:
                self.logger("Encrypting archive", archive_path=archive_path)
                self.encrypt_fn(archive_path)

            # compute checksum
            checksum = self._sha256_file(archive_path)
            self.logger("Archive created", path=archive_path, sha256=checksum)

            # record in DB archival_index atomically
            with self._connect() as conn:
                # Use immediate transaction to avoid concurrent inserts
                conn.execute("BEGIN IMMEDIATE;")
                # validate uniqueness again and insert
                cur = conn.execute("SELECT MAX(case_number) FROM archival_index")
                current_max = cur.fetchone()[0] or 0
                if int(current_max) + 1 != case_number:
                    # race detected — choose new number or raise
                    new_case_number = int(current_max) + 1
                    # rename archive and directory
                    new_case_dir_name = f"case_{new_case_number:04d}"
                    new_archive_filename = f"{new_case_dir_name}.tar.gz"
                    new_archive_path = os.path.join(self.base_cases_dir, new_archive_filename)
                    os.rename(archive_path, new_archive_path)
                    archive_path = new_archive_path
                    case_number = new_case_number
                # insert entry
                self._insert_archive_index(conn, case_number, archive_path, summary_dict)

            # final cleanup
            if cleanup_temp:
                shutil.rmtree(tmpdir, ignore_errors=True)

            # optionally remove ephemeral mounts, ensure callers can pass a cleanup callback
            return {"case_number": case_number, "archive_path": archive_path, "sha256": checksum}
        except Exception as e:
            raise ArchiveError("Failed to archive investigation") from e
        finally:
            if os.path.exists(tmpdir):
                try:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                except Exception:
                    pass
