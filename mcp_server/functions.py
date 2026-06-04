

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.database import (initialize_database, clear_database,
                           execute_safe_query, get_connection)
from core.assertions import run_assertion, AssertionFailedError, TemporalContradictionError
from core.coverage import initialize_coverage, record_tool_call, get_coverage_report, check_can_conclude
from core.ledger import log_start, log_tool, log_assertion, log_end

from tools.mft_parser import extract_mft_timeline
from tools.amcache_parser import extract_amcache
from tools.prefetch_parser import extract_prefetch
from tools.evtx_parser import extract_evtx_events
from tools.registry_parser import extract_registry_runkeys

initialize_database()


# ─────────────────────────────────────────────────────────────
# HELPER: Count rows in a table (used by TEST_MODE wrappers)
# ─────────────────────────────────────────────────────────────

def _count_rows(table):
    """Return integer count of rows currently in a table."""
    try:
        rows = execute_safe_query(f"SELECT COUNT(*) as n FROM {table}")
        return rows[0]['n'] if rows else 0
    except Exception:
        return 0


# ─────────────────────────────────────────────────────────────
# INVESTIGATION LIFECYCLE
# ─────────────────────────────────────────────────────────────

def start_investigation(image_path, case_type="generic"):
    """
    Initialise a new investigation.

    FIX: When image_path == "TEST_MODE" we do NOT call clear_database().
         create_test_data.py already loaded the demo evidence.
         Calling clear_database() here destroyed all of it.
    """
    if image_path != "TEST_MODE":
        clear_database()                        # real image → fresh start
    # TEST_MODE → skip clear, demo data is already in the DB

    cov = initialize_coverage(case_type)
    log_start({"image_path": image_path, "case_type": case_type})

    return {
        "status": "initialized",
        "image_path": image_path,
        "case_type": case_type,
        "coverage": cov,
        "instructions": [
            "1. Call get_mft_timeline(image_path) to build file system timeline",
            "2. Call get_prefetch(image_path) to find execution evidence",
            "3. Call get_amcache(image_path) for additional execution records",
            "4. Call get_registry_runkeys(image_path) to check persistence",
            "5. Call get_evtx_events(image_path) for user/security events",
            "6. Call query_evidence(table, sql_filter) to explore the data",
            "7. Call submit_claim(claim_json) to verify specific findings",
            "8. Call get_coverage_status() to check investigation progress",
            "9. Call conclude_investigation(summary) when all categories covered"
        ]
    }


# ─────────────────────────────────────────────────────────────
# SIFT TOOL WRAPPERS
# Each wrapper handles TEST_MODE by reading existing DB rows
# instead of running a subprocess on a non-existent file path.
# ─────────────────────────────────────────────────────────────

def get_mft_timeline(image_path):
    if image_path == "TEST_MODE":
        count = _count_rows("mft_events")
        r = {
            "status": "success", "table": "mft_events",
            "rows_inserted": count, "sha256": "test_mode",
            "schema": {
                "filename": "str", "full_path": "str",
                "created_at": "datetime", "modified_at": "datetime",
                "file_size": "int", "action": "str (create/delete/access/modify)"
            },
            "message": (
                f"{count} MFT events loaded from test dataset. "
                "Query using query_evidence or submit_claim on 'mft_events'. "
                "IMPORTANT: 'delete' action rows prove a file was removed."
            )
        }
    else:
        r = extract_mft_timeline(image_path)

    record_tool_call("get_mft_timeline")
    log_tool("get_mft_timeline", {"image_path": image_path}, r)
    return r


def get_amcache(image_path):
    if image_path == "TEST_MODE":
        count = _count_rows("amcache_entries")
        r = {
            "status": "success", "table": "amcache_entries",
            "rows_inserted": count, "sha256": "test_mode",
            "schema": {
                "program_name": "str", "program_path": "str",
                "sha256_hash": "str (SHA256 of binary)", "first_run_time": "datetime"
            },
            "message": (
                f"{count} AmCache entries loaded from test dataset. "
                "Query using query_evidence or submit_claim on 'amcache_entries'."
            )
        }
    else:
        r = extract_amcache(image_path)

    record_tool_call("get_amcache")
    log_tool("get_amcache", {"image_path": image_path}, r)
    return r


def get_prefetch(image_path):
    if image_path == "TEST_MODE":
        count = _count_rows("prefetch_events")
        r = {
            "status": "success", "table": "prefetch_events",
            "rows_inserted": count, "sha256": "test_mode",
            "schema": {
                "executable_name": "str (includes .pf hash suffix, e.g. EVIL.EXE-AB12CD34.pf)",
                "last_run_time": "datetime",
                "run_count": "int"
            },
            "message": (
                f"{count} prefetch records loaded from test dataset. "
                "Prefetch proves execution even after file deletion. "
                "Use LIKE for name matching: executable_name LIKE '%EVIL%'"
            )
        }
    else:
        r = extract_prefetch(image_path)

    record_tool_call("get_prefetch")
    log_tool("get_prefetch", {"image_path": image_path}, r)
    return r


def get_evtx_events(image_path, event_ids=None):
    if image_path == "TEST_MODE":
        count = _count_rows("evtx_events")
        r = {
            "status": "success", "table": "evtx_events",
            "rows_inserted": count, "sha256": "test_mode",
            "schema": {
                "event_id": "int", "timestamp": "datetime",
                "computer": "str", "username": "str", "description": "str"
            },
            "message": (
                f"{count} event log entries loaded from test dataset. "
                "Key IDs: 4688=process_create, 4624=logon, 1102=audit_log_cleared, "
                "4698=sched_task, 7045=service_install"
            )
        }
    else:
        r = extract_evtx_events(image_path, event_ids)

    record_tool_call("get_evtx_events")
    log_tool("get_evtx_events", {"image_path": image_path}, r)
    return r


def get_registry_runkeys(image_path):
    if image_path == "TEST_MODE":
        count = _count_rows("registry_runkeys")
        r = {
            "status": "success", "table": "registry_runkeys",
            "rows_inserted": count, "sha256": "test_mode",
            "schema": {
                "hive": "str (HKCU/HKLM)", "key_path": "str",
                "value_name": "str", "value_data": "str (usually a file path)"
            },
            "message": (
                f"{count} registry persistence entries loaded from test dataset. "
                "Suspicious entries: value_data points outside System32 or WindowsApps."
            )
        }
    else:
        r = extract_registry_runkeys(image_path)

    record_tool_call("get_registry_runkeys")
    log_tool("get_registry_runkeys", {"image_path": image_path}, r)
    return r


# ─────────────────────────────────────────────────────────────
# QUERY & ASSERTION ENGINE
# ─────────────────────────────────────────────────────────────

def query_evidence(table, sql_filter="1=1", limit=20):
    """
    Query any evidence table with a WHERE clause.

    Args:
        table       — one of: mft_events, prefetch_events, amcache_entries,
                      evtx_events, registry_runkeys, confirmed_findings
        sql_filter  — WHERE clause (no WHERE keyword), e.g. "action = 'delete'"
                      Use LIKE for partial matches: "executable_name LIKE '%evil%'"
                      Use UPPER() for case-insensitive: "UPPER(filename) LIKE '%MIMIKATZ%'"
        limit       — max rows to return (default 20, max 100)

    Returns dict with 'query', 'row_count', 'results'.
    If 0 rows: results is [] — this means the claim is NOT supported by evidence.
    """
    valid_tables = [
        'mft_events', 'prefetch_events', 'amcache_entries',
        'evtx_events', 'registry_runkeys', 'confirmed_findings'
    ]
    if table not in valid_tables:
        return {
            "error": f"Invalid table: '{table}'",
            "valid_tables": valid_tables,
            "hint": "Run the get_X() tools first to populate tables."
        }

    limit = min(int(limit), 100)

    # Handle sql_filter = None or empty
    if not sql_filter or sql_filter.strip() in ('', 'None', 'null'):
        sql_filter = "1=1"

    sql = f"SELECT * FROM {table} WHERE {sql_filter} LIMIT {limit}"

    try:
        rows = execute_safe_query(sql)
        return {
            "query": sql,
            "row_count": len(rows),
            "results": rows,
            "note": (
                "0 results = no evidence for that filter. "
                "Try broader filter with LIKE or UPPER(). "
                "Check table is populated: query_evidence with sql_filter='1=1'"
            ) if len(rows) == 0 else f"{len(rows)} rows found."
        }
    except Exception as e:
        # Give the agent the error and a sample of real data so it can fix the SQL
        try:
            sample = execute_safe_query(f"SELECT * FROM {table} LIMIT 3")
        except Exception:
            sample = []
        return {
            "error": f"SQL error: {str(e)}",
            "query_attempted": sql,
            "hint": (
                "Check sql_filter syntax. String values need single quotes: "
                "filename = 'evil.exe' not filename = \"evil.exe\""
            ),
            "sample_data": sample
        }


def submit_claim(claim_json):
    """
    THE ASSERTION GATE.

    Submit a forensic claim with SQL evidence pointer.
    Python executes the SQL — claim is CONFIRMED or REJECTED.
    The LLM cannot bypass this gate.

    claim_json must contain:
      claim           — plain English description of the finding
      evidence_table  — which SQLite table proves it
      sql_filter      — WHERE clause that selects the proving rows
      expected_result — "at_least_one_row" | "no_rows" | "count_equals_N"
      mitre_technique — (optional) e.g. "T1059.003"

    Returns:
      On success: {"status": "CONFIRMED", "finding_id": ..., "confidence_tier": ...}
      On temporal contradiction: {"status": "TEMPORAL_CONTRADICTION", "detail": ...}
      On failure: {"status": "ASSERTION_FAILED", "detail": ...}
        — detail contains the actual DB data so agent can revise

    Never raises — always returns something the agent can act on.
    """
    try:
        finding = run_assertion(claim_json)
        log_assertion(claim_json.get('claim', ''), "CONFIRMED", finding['finding_id'])
        return {
            "status": "CONFIRMED",
            "finding_id": finding['finding_id'],
            "confidence_tier": finding['confidence_tier'],
            "rows_proved": finding['rows_matched'],
            "mitre": finding['mitre_technique'],
            "message": (
                f"Finding {finding['finding_id']} confirmed. "
                f"Confidence: {finding['confidence_tier']}. "
                "Continue investigating other artifact categories."
            )
        }
    except TemporalContradictionError as e:
        log_assertion(claim_json.get('claim', ''), "TEMPORAL_CONTRADICTION")
        return {
            "status": "TEMPORAL_CONTRADICTION",
            "detail": str(e),
            "action_required": (
                "This is HIGH-VALUE evidence of anti-forensics. "
                "Submit a SEPARATE claim about this temporal contradiction "
                "with evidence_table matching the artifact that shows the contradiction."
            )
        }
    except AssertionFailedError as e:
        log_assertion(claim_json.get('claim', ''), "ASSERTION_FAILED")
        return {
            "status": "ASSERTION_FAILED",
            "detail": str(e),
            "action_required": (
                "Revise your claim to match the actual data shown above. "
                "Do NOT submit the same claim again unchanged."
            )
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "detail": str(e),
            "action_required": "Check claim_json has all required fields: claim, evidence_table, sql_filter, expected_result"
        }


def get_coverage_status():
    """
    Returns investigation coverage report.

    Check this after every few tool calls.
    conclude_investigation() will BLOCK unless all mandatory categories are covered.
    """
    return get_coverage_report()


def conclude_investigation(analyst_summary):
    """
    Generate the final DFIR report.

    BLOCKS with error if mandatory investigation categories are not covered.
    This is a Python gate — not a suggestion.

    Returns full report with CONFIRMED and INFERRED findings,
    coverage stats, and audit trail reference.
    """
    # Coverage gate — raises ValueError if mandatory categories are missing
    # The ValueError is caught by dispatch_tool and returned as an error
    # so the agent knows exactly which tool to call next
    check_can_conclude()

    findings = execute_safe_query(
        "SELECT * FROM confirmed_findings ORDER BY created_at"
    )
    coverage = get_coverage_report()

    confirmed = [f for f in findings if f.get('confidence_tier') == 'CONFIRMED']
    inferred = [f for f in findings if f.get('confidence_tier') == 'INFERRED']

    report = {
        "status": "COMPLETE",
        "analyst_summary": analyst_summary,
        "evidence_integrity": (
            "All findings SQL-verified. No LLM assertion accepted without Python confirmation. "
            "Temporal contradiction engine ran on every claim."
        ),
        "coverage": coverage,
        "total_findings": len(findings),
        "confirmed_findings": confirmed,
        "inferred_findings": inferred,
        "finding_ids": [f['finding_id'] for f in findings],
        "mitre_techniques": list(set(
            f['mitre_technique'] for f in findings
            if f.get('mitre_technique') and f['mitre_technique'] != 'unspecified'
        )),
        "audit_trail": "logs/audit.jsonl — run: python3 replay.py --audit",
        "replay_any_finding": "python3 replay.py --finding_id <ID>"
    }

    log_end({
        "total_findings": len(findings),
        "coverage": coverage.get('coverage_percentage', 0),
        "confirmed": len(confirmed),
        "inferred": len(inferred)
    })

    return report


def replay_finding(finding_id):
    """
    Re-execute the SQL that proved a finding. Verifies evidence is unchanged.
    """
    findings = execute_safe_query(
        f"SELECT * FROM confirmed_findings WHERE finding_id = '{finding_id}'"
    )
    if not findings:
        all_ids = execute_safe_query(
            "SELECT finding_id, claim FROM confirmed_findings"
        )
        return {
            "error": f"Finding ID '{finding_id}' not found.",
            "available_findings": all_ids
        }

    f = findings[0]
    re_run = execute_safe_query(f['sql_executed'])

    return {
        "finding_id": finding_id,
        "claim": f['claim'],
        "sql_proved_it": f['sql_executed'],
        "rows_at_proof_time": f['rows_matched'],
        "rows_now": len(re_run),
        "verdict": "VERIFIED — evidence unchanged" if f['rows_matched'] == len(re_run) else "WARNING — row count changed",
        "confidence": f['confidence_tier'],
        "sha256_chain": f['sha256_of_evidence'],
        "proven_at": f.get('created_at', 'unknown'),
        "sample_evidence": re_run[:3]
    }