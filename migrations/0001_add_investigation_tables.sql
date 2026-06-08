-- Migration: add investigations and supporting tables
-- Path: migrations/0001_add_investigation_tables.sql

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_number INTEGER UNIQUE,
  status TEXT,
  system_profile JSON,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  archived_at TEXT,
  summary TEXT
);

CREATE TABLE IF NOT EXISTS investigation_state (
  investigation_id INTEGER PRIMARY KEY,
  state_json TEXT,
  state_checksum TEXT,
  last_updated TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hypotheses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER,
  hypothesis_text TEXT,
  status TEXT,
  confidence REAL,
  evidence_refs JSON,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER,
  artifact_type TEXT,
  source_path TEXT,
  size INTEGER,
  status TEXT,
  confidence REAL,
  parsing_errors TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER,
  step_name TEXT,
  state_json TEXT,
  state_checksum TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reasoning_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  investigation_id INTEGER,
  prompt TEXT,
  model_used TEXT,
  response TEXT,
  tokens_used INTEGER,
  quality_score REAL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS archival_index (
  case_number INTEGER PRIMARY KEY,
  archive_path TEXT,
  summary TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_investigation_id_evidence ON evidence_items (investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_id_hypotheses ON hypotheses (investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_id_checkpoints ON checkpoints (investigation_id);
