

import json, os
from datetime import datetime

LEDGER_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'audit.jsonl')


def _write(entry):
    os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)
    with open(LEDGER_PATH, 'a') as f:
        f.write(json.dumps(entry, default=str) + '\n')


def log_start(case_info):
    # Archive previous log if exists
    if os.path.exists(LEDGER_PATH):
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        os.rename(LEDGER_PATH, LEDGER_PATH + f'.{ts}.bak')
    _write({"type": "start", "timestamp": datetime.utcnow().isoformat(), "case": case_info})


def log_tool(tool_name, params, result):
    _write({"type": "tool_call", "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name, "params": params, "result_summary": result})


def log_assertion(claim, result, finding_id=None):
    _write({"type": "assertion", "timestamp": datetime.utcnow().isoformat(),
            "claim": claim[:120], "result": result, "finding_id": finding_id})


def log_end(report):
    _write({"type": "complete", "timestamp": datetime.utcnow().isoformat(),
            "summary": report})


def read_all():
    if not os.path.exists(LEDGER_PATH):
        return []
    entries = []
    with open(LEDGER_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries