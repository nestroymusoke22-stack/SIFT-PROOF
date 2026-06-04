

import uuid
import json
from datetime import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.database import get_connection, execute_safe_query


class AssertionFailedError(Exception):
    """Raised when SQL finds no evidence for the claim."""
    pass


class TemporalContradictionError(Exception):
    """Raised when timestamps form an impossible sequence — anti-forensics indicator."""
    pass


def run_assertion(claim_json):
    """
    The gate function. Every finding must pass through here.

    claim_json must have:
      claim          — human readable description
      evidence_table — which SQLite table to check
      sql_filter     — WHERE clause that proves the claim
      expected_result — "at_least_one_row" | "no_rows" | "count_equals_N"
      mitre_technique — (optional) MITRE ATT&CK ID

    Returns: finding dict if CONFIRMED
    Raises: AssertionFailedError if SQL finds no supporting evidence
    Raises: TemporalContradictionError if timestamps are impossible
    """
    required = ['claim', 'evidence_table', 'sql_filter', 'expected_result']
    for field in required:
        if field not in claim_json:
            raise AssertionFailedError(
                f"CLAIM REJECTED — Missing field: '{field}'\n"
                f"Required fields: {required}"
            )

    table = claim_json['evidence_table']
    sql_filter = claim_json['sql_filter']
    expected = claim_json['expected_result']

    valid_tables = ['mft_events', 'amcache_entries', 'prefetch_events',
                    'evtx_events', 'registry_runkeys']

    if table not in valid_tables:
        raise AssertionFailedError(
            f"CLAIM REJECTED — Invalid table: '{table}'\n"
            f"Valid tables: {valid_tables}\n"
            f"Make sure you ran the corresponding tool first."
        )

    sql = f"SELECT * FROM {table} WHERE {sql_filter}"
    print(f"[ASSERTION] Running: {sql}")

    try:
        rows = execute_safe_query(sql)
    except Exception as e:
        # Give the LLM the exact error so it can fix the SQL
        raise AssertionFailedError(
            f"CLAIM REJECTED — SQL error: {e}\n"
            f"Query attempted: {sql}\n"
            f"Fix: check your sql_filter syntax. "
            f"String values need single quotes: filename = 'evil.exe'"
        )

    count = len(rows)

    # Check expectation
    passed = False
    reason = ""

    if expected == "at_least_one_row":
        passed = count > 0
        reason = f"Expected ≥1 row, found {count} rows matching: {sql_filter}"

    elif expected == "no_rows":
        passed = count == 0
        reason = f"Expected 0 rows, found {count} rows — data contradicts claim"

    elif expected.startswith("count_equals_"):
        n = int(expected.split("_")[-1])
        passed = count == n
        reason = f"Expected {n} rows, found {count}"

    if not passed:
        # Get sample of actual data so LLM can revise intelligently
        sample = execute_safe_query(f"SELECT * FROM {table} LIMIT 5")
        raise AssertionFailedError(
            f"\n{'='*55}\n"
            f"ASSERTION FAILED — CLAIM REJECTED\n"
            f"{'='*55}\n"
            f"Your claim: {claim_json['claim']}\n"
            f"SQL executed: {sql}\n"
            f"Result: {reason}\n\n"
            f"Actual data in {table} (sample of 5 rows):\n"
            f"{json.dumps(sample, indent=2, default=str)}\n"
            f"{'='*55}\n"
            f"ACTION: Revise your claim to match the actual data above."
        )

    # Assertion passed — run temporal checks before confirming
    temporal = _run_temporal_checks(claim_json, rows)
    if temporal['contradiction']:
        raise TemporalContradictionError(
            f"\n{'='*55}\n"
            f"⚠️  TEMPORAL CONTRADICTION — POSSIBLE ANTI-FORENSICS\n"
            f"{'='*55}\n"
            f"Claim: {claim_json['claim']}\n"
            f"Contradiction: {temporal['description']}\n"
            f"Event A: {temporal['event_a']}\n"
            f"Event B: {temporal['event_b']}\n"
            f"Impossible sequence: {temporal['sequence']}\n\n"
            f"This may indicate: Timestomping, Rootkit DKOM, Clock manipulation\n"
            f"ACTION: Submit a separate claim about the anti-forensics indicator.\n"
            f"This is HIGH-VALUE evidence — do not ignore it.\n"
            f"{'='*55}"
        )

    # All checks passed — assign confidence tier via Python logic (not LLM)
    tier = _compute_confidence(claim_json, rows)

    finding = {
        "finding_id": str(uuid.uuid4())[:8],
        "claim": claim_json['claim'],
        "evidence_table": table,
        "sql_filter": sql_filter,
        "sql_executed": sql,
        "rows_matched": count,
        "sample_rows": rows[:3],
        "assertion_result": "CONFIRMED",
        "confidence_tier": tier,
        "temporal_check": "PASS",
        "mitre_technique": claim_json.get('mitre_technique', 'unspecified'),
        "sha256_of_evidence": rows[0].get('sha256_of_raw_output', '') if rows else '',
        "proven_at": datetime.utcnow().isoformat()
    }

    _store_finding(finding)
    print(f"[ASSERTION] ✓ CONFIRMED — ID: {finding['finding_id']} — Tier: {tier}")
    return finding


def _run_temporal_checks(claim_json, rows):
    """
    Cross-table SQL joins to detect impossible event sequences.
    File executed after deletion. Process ran before installation. Etc.
    No LLM involved — pure SQL.
    """
    result = {"contradiction": False, "description": "", "event_a": "", "event_b": "", "sequence": ""}
    table = claim_json.get('evidence_table', '')

    # Check 1: Prefetch says file ran, but MFT says it was deleted earlier
    if table == 'prefetch_events':
        for row in rows:
            exe = row.get('executable_name', '')
            if not exe:
                continue
            # Strip the .pf extension and hash suffix (MIMIKATZ.EXE-ABCD1234.pf → MIMIKATZ)
            base = exe.split('.')[0].upper() if '.' in exe else exe.upper()
            if len(base) < 3:
                continue

            check = execute_safe_query(f"""
                SELECT mft.full_path, mft.modified_at as deleted_at,
                       pre.last_run_time as executed_at
                FROM mft_events mft
                JOIN prefetch_events pre
                  ON UPPER(mft.filename) LIKE '%{base}%'
                WHERE mft.action = 'delete'
                  AND mft.modified_at < pre.last_run_time
                LIMIT 1
            """)
            if check:
                result['contradiction'] = True
                result['description'] = "File executed AFTER it was deleted from disk"
                result['event_a'] = f"MFT: {exe} deleted at {check[0].get('deleted_at', '?')}"
                result['event_b'] = f"Prefetch: executed at {check[0].get('executed_at', '?')}"
                result['sequence'] = "DELETION → EXECUTION (physically impossible)"
                return result

    # Check 2: AmCache first-seen is AFTER Prefetch execution time
    if table == 'prefetch_events':
        for row in rows:
            exe = row.get('executable_name', '').split('.')[0].upper()
            exec_time = row.get('last_run_time', '')
            if not exe or not exec_time:
                continue

            check = execute_safe_query(f"""
                SELECT program_name, first_run_time
                FROM amcache_entries
                WHERE UPPER(program_name) LIKE '%{exe}%'
                  AND first_run_time > '{exec_time}'
                LIMIT 1
            """)
            if check:
                result['contradiction'] = True
                result['description'] = "Program executed before it was first seen by AmCache"
                result['event_a'] = f"Prefetch execution: {exec_time}"
                result['event_b'] = f"AmCache first seen: {check[0].get('first_run_time', '?')}"
                result['sequence'] = "EXECUTION → FIRST_INSTALLATION (impossible)"
                return result

    # Check 3: User activity in event logs before account creation
    if table == 'evtx_events':
        for row in rows:
            user = row.get('username', '')
            ts = row.get('timestamp', '')
            if not user or not ts or user.upper() in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                continue

            check = execute_safe_query(f"""
                SELECT e_act.timestamp as activity_time,
                       e_create.timestamp as creation_time
                FROM evtx_events e_act
                JOIN evtx_events e_create ON e_create.event_id = 4720
                WHERE e_act.event_id IN (4624, 4625, 4648)
                  AND e_act.username = '{user}'
                  AND e_create.username = '{user}'
                  AND e_act.timestamp < e_create.timestamp
                LIMIT 1
            """)
            if check:
                result['contradiction'] = True
                result['description'] = f"User '{user}' was active before their account existed"
                result['event_a'] = f"Login at: {check[0].get('activity_time', '?')}"
                result['event_b'] = f"Account created at: {check[0].get('creation_time', '?')}"
                result['sequence'] = "USER_ACTIVITY → ACCOUNT_CREATION (impossible)"
                return result

    return result


def _compute_confidence(claim_json, rows):
    """
    Confidence tier computed by Python logic — never by the LLM.
    CONFIRMED: direct single-table evidence, unambiguous
    INFERRED:  relies on cross-table reasoning or indirect correlation
    """
    if 'JOIN' in claim_json.get('sql_filter', '').upper():
        return "INFERRED"
    return "CONFIRMED" if len(rows) >= 1 else "INFERRED"


def _store_finding(finding):
    """Writes a verified finding to the database."""
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO confirmed_findings
        (finding_id, claim, evidence_table, sql_filter, sql_executed,
         rows_matched, assertion_result, confidence_tier, temporal_check,
         mitre_technique, sha256_of_evidence)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        finding['finding_id'], finding['claim'], finding['evidence_table'],
        finding['sql_filter'], finding['sql_executed'], finding['rows_matched'],
        finding['assertion_result'], finding['confidence_tier'],
        finding['temporal_check'], finding['mitre_technique'],
        finding['sha256_of_evidence']
    ))
    conn.commit()
    conn.close()