import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.volatility_parser import (extract_process_list,
    extract_network_connections, extract_cmdlines, extract_malfind)

from core.database import (initialize_database, clear_database,
                           execute_safe_query)
from core.assertions import run_assertion, AssertionFailedError, TemporalContradictionError
from core.coverage import initialize_coverage, record_tool_call, get_coverage_report, check_can_conclude
from core.ledger import log_start, log_tool, log_assertion, log_end

from tools.mft_parser import extract_mft_timeline
from tools.amcache_parser import extract_amcache
from tools.prefetch_parser import extract_prefetch
from tools.evtx_parser import extract_evtx_events
from tools.registry_parser import extract_registry_run as extract_registry_runkeys

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


_MAX_FIELD_CHARS = 160


def _truncate_row(row, max_chars=_MAX_FIELD_CHARS):
    """
    Shrink a single DB row before it is handed to the LLM.

    Drops the bulky chain-of-custody hash and clips any oversized string field
    so a wide row (e.g. a long cmdline or registry blob) can never blow up the
    token budget.
    """
    slim = {}
    for k, v in dict(row).items():
        if k == 'sha256_of_raw_output':
            continue
        if isinstance(v, str) and len(v) > max_chars:
            v = v[:max_chars] + f"…(+{len(v) - max_chars} chars)"
        slim[k] = v
    return slim


# ─────────────────────────────────────────────────────────────
# INVESTIGATION LIFECYCLE
# ─────────────────────────────────────────────────────────────

def start_investigation(image_path, case_type="generic"):
    """
    Initialise a new investigation.
     For a real image we wipe all tables for a clean run. In TEST_MODE the demo
    evidence has already been loaded by create_test_data.py, so we must NOT
    clear it.
    """
    if "memory" in case_type.lower():
        case_type = "memory_analysis"

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
        # extract_mft_timeline() routes directories → native walker,
        # image files → fls/mactime, and returns a JSON error otherwise.
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
        # extract_prefetch() routes directories → native .pf parser (real mtimes),
        # prefetch dirs → PECmd, and returns a JSON error otherwise.
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
    valid_tables = [
        'mft_events', 'prefetch_events', 'amcache_entries',
        'evtx_events', 'registry_runkeys', 'confirmed_findings',
        'memory_processes', 'memory_network',
        'memory_cmdlines',  'memory_injections'
    ]
    if table not in valid_tables:
        return {
            "error": f"Invalid table: '{table}'",
            "valid_tables": valid_tables,
            "hint": "Run the get_X() tools first to populate tables."
        }
    
    # Cap rows hard so a huge table can never explode the LLM context window
    # (Groq free-tier TPM / HTTP 413 protection).
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, 25))

    if not sql_filter or sql_filter.strip() in ('', 'None', 'null'):
        sql_filter = "1=1"

    sql = f"SELECT * FROM {table} WHERE {sql_filter} LIMIT {limit}"

    try:
        total = _count_rows(table)
        rows = execute_safe_query(sql)
        slim = [_truncate_row(r) for r in rows]
        return {
            "query": sql,
            "row_count": len(slim),
            "table_total_rows": total,
            "results": slim,
            "note": (
                "0 results = no evidence for that filter. "
                "Try broader filter with LIKE or UPPER(). "
                "Check table is populated: query_evidence with sql_filter='1=1'"
            ) if len(slim) == 0 else (
                f"Showing {len(slim)} of {total} total rows in {table} "
                f"(capped at {limit}). Long fields are truncated; narrow your "
                f"sql_filter to inspect specific rows."
            )
        }
    except Exception as e:
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
    if not claim_json or not isinstance(claim_json, dict):
        return {
            "status": "ERROR",
            "detail": "Invalid or missing claim configuration payload.",
            "action_required": "Provide a valid claim JSON dictionary object."
        }

    sql_filt = claim_json.get('sql_filter', '')
    if not sql_filt or str(sql_filt).strip() in ('', 'None', 'null'):
        claim_json['sql_filter'] = "1=1"

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
                f"Continue investigating other artifact categories."
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


# ─────────────────────────────────────────────────────────────
# COVERAGE & CONCLUSION
# ─────────────────────────────────────────────────────────────

def get_coverage_status():
    """Return the current coverage report (mandatory categories covered/missing)."""
    return get_coverage_report()


def conclude_investigation(analyst_summary=""):
    """
    Finalize the investigation. Fails (without crashing) if mandatory coverage
    categories are still missing, returning the gap so the agent can fill it.
    """
    try:
        check_can_conclude()
    except ValueError as e:
        return {
            "status": "INCOMPLETE",
            "detail": str(e),
            "coverage": get_coverage_report(),
            "action_required": (
                "Run the missing collection tools listed above, then call "
                "conclude_investigation again."
            )
        }
    except Exception as e:
        return {"status": "ERROR", "detail": f"Coverage check failed: {e}"}

    try:
        findings = execute_safe_query(
            "SELECT finding_id, claim, confidence_tier, temporal_check, "
            "mitre_technique FROM confirmed_findings"
        )
    except Exception:
        findings = []

    coverage = get_coverage_report()
    report = {
        "status": "COMPLETE",
        "analyst_summary": analyst_summary,
        "total_findings": len(findings),
        "findings": [_truncate_row(f) for f in findings],
        "coverage": coverage,
        "anti_forensics_flags": [
            f.get('finding_id') for f in findings
            if str(f.get('temporal_check', '')).upper() not in ('PASS', '')
        ],
    }
    log_end({"total_findings": len(findings),
             "coverage_percentage": coverage.get("coverage_percentage", 0)})
    return report


# ─────────────────────────────────────────────────────────────
# MEMORY-ANALYSIS TOOL WRAPPERS (Volatility3)
# Each wrapper handles TEST_MODE and never raises — failures come back
# as a clean JSON error so the agent can pivot to another data source.
# ─────────────────────────────────────────────────────────────

def _memory_tool(tool_name, table, extractor, image_path, test_schema, test_msg):
    if image_path == "TEST_MODE":
        count = _count_rows(table)
        r = {
            "status": "success", "table": table,
            "rows_inserted": count, "sha256": "test_mode",
            "schema": test_schema, "message": test_msg.format(count=count),
        }
    else:
        try:
            r = extractor(image_path)
        except Exception as e:
            r = {"status": "error", "table": table,
                 "rows_inserted": 0, "error": f"{tool_name} failed: {e}"}

    record_tool_call(tool_name)
    log_tool(tool_name, {"image_path": image_path}, r)
    return r


def get_process_list(image_path):
    return _memory_tool(
        "get_process_list", "memory_processes", extract_process_list, image_path,
        {"pid": "int", "ppid": "int", "process_name": "str",
         "create_time": "datetime", "threads": "int", "handles": "int"},
        "{count} processes loaded. Flag unusual parent/child PPIDs and "
        "renamed system binaries (svchost/lsass from odd paths).")


def get_network_connections(image_path):
    return _memory_tool(
        "get_network_connections", "memory_network", extract_network_connections,
        image_path,
        {"pid": "int", "process_name": "str", "proto": "str",
         "local_addr": "str", "remote_addr": "str", "remote_port": "str",
         "state": "str"},
        "{count} network connections loaded. Flag ESTABLISHED sessions from "
        "non-network processes and foreign remote IPs.")


def get_cmdlines(image_path):
    return _memory_tool(
        "get_cmdlines", "memory_cmdlines", extract_cmdlines, image_path,
        {"pid": "int", "process_name": "str", "cmdline": "str"},
        "{count} command lines loaded. Flag base64 PowerShell (-EncodedCommand) "
        "and LOLBins (certutil/mshta/regsvr32).")


def get_malfind(image_path):
    return _memory_tool(
        "get_malfind", "memory_injections", extract_malfind, image_path,
        {"pid": "int", "process_name": "str", "start_va": "str",
         "protection": "str", "file_output": "str"},
        "{count} suspicious memory regions. PAGE_EXECUTE_READWRITE = injected "
        "shellcode/reflective DLL.")