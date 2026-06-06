import json
import os
from datetime import datetime

TRACE_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'logs', 'agent_execution_trace.jsonl'
)


def _write(event_type, data):
    os.makedirs(os.path.dirname(TRACE_PATH), exist_ok=True)
    entry = {
        "ts": datetime.utcnow().isoformat(timespec='microseconds'),
        "type": event_type,
        **data
    }
    line = json.dumps(entry, default=str) + '\n'
    with open(TRACE_PATH, 'a') as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())   # Force to disk — survives power loss


def trace_start(image_path, case_type, backend_info):
    _write("INVESTIGATION_START", {
        "image_path": image_path,
        "case_type": case_type,
        "backend": backend_info
    })


def trace_iteration(iteration, max_iterations):
    _write("ITERATION_BEGIN", {
        "iteration": iteration,
        "max_iterations": max_iterations
    })


def trace_llm_response(content, tool_calls_count):
    _write("LLM_RESPONSE", {
        "content_preview": (content or "")[:300],
        "tool_calls_count": tool_calls_count
    })


def trace_tool_call(tool_name, arguments):
    _write("TOOL_CALL", {
        "tool": tool_name,
        "arguments": arguments
    })


def trace_tool_result(tool_name, result_preview, finding_id=None):
    entry = {
        "tool": tool_name,
        "result_preview": result_preview[:400] if result_preview else "",
    }
    if finding_id:
        entry["finding_id"] = finding_id
    _write("TOOL_RESULT", entry)


def trace_assertion(claim, result, finding_id=None):
    entry = {
        "claim_preview": claim[:120],
        "result": result
    }
    if finding_id:
        entry["finding_id"] = finding_id
    _write("ASSERTION", entry)


def trace_end(status, total_findings, coverage_pct):
    _write("INVESTIGATION_END", {
        "status": status,
        "total_findings": total_findings,
        "coverage_pct": coverage_pct
    })
