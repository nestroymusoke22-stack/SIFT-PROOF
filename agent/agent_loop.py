import json
import re
import sys
import os
import argparse
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.llm_client import chat, parse_tool_call, get_backend_info
import mcp_server.functions as sift

# ── New modules (progress + trace) ────────────────────────────────────────────
from agent.progress_state import (load_progress, save_progress,
                                   mark_complete, clear_progress)
from core.execution_trace import (trace_start, trace_iteration,
                                   trace_tool_call, trace_tool_result,
                                   trace_llm_response, trace_end)
try:
    from core.database import execute_safe_query
except Exception:
    execute_safe_query = lambda sql: []


SYSTEM_PROMPT = """You are SIFT-PROOF, an autonomous digital forensic analyst.

You investigate disk images AND memory images for evidence of malicious activity.
You communicate ONLY by outputting a single JSON object per response.

OUTPUT FORMAT — you must always output exactly one JSON object:
{"tool": "TOOL_NAME", "arguments": {"param": "value"}}

To finish the investigation:
{"tool": "DONE", "arguments": {"summary": "your full analysis here"}}

AVAILABLE TOOLS — DISK ANALYSIS:
1.  start_investigation     — {"tool": "start_investigation", "arguments": {"image_path": "PATH", "case_type": "windows_compromise"}}
2.  get_mft_timeline         — {"tool": "get_mft_timeline", "arguments": {"image_path": "PATH"}}
3.  get_amcache             — {"tool": "get_amcache", "arguments": {"image_path": "PATH"}}
4.  get_prefetch            — {"tool": "get_prefetch", "arguments": {"image_path": "PATH"}}
5.  get_evtx_events         — {"tool": "get_evtx_events", "arguments": {"image_path": "PATH"}}
6.  get_registry_runkeys    — {"tool": "get_registry_runkeys", "arguments": {"image_path": "PATH"}}
7.  query_evidence          — {"tool": "query_evidence", "arguments": {"table": "TABLE", "sql_filter": "FILTER", "limit": 20}}
8.  submit_claim            — {"tool": "submit_claim", "arguments": {"claim": "TEXT", "evidence_table": "TABLE", "sql_filter": "FILTER", "expected_result": "at_least_one_row", "mitre_technique": "TXXXX"}}
9.  get_coverage_status     — {"tool": "get_coverage_status", "arguments": {}}
10. conclude_investigation  — {"tool": "conclude_investigation", "arguments": {"analyst_summary": "FULL SUMMARY"}}

AVAILABLE TOOLS — MEMORY ANALYSIS (use these when given a .raw/.mem/.dmp file):
11. get_process_list        — {"tool": "get_process_list", "arguments": {"image_path": "PATH"}}
12. get_network_connections — {"tool": "get_network_connections", "arguments": {"image_path": "PATH"}}
13. get_cmdlines            — {"tool": "get_cmdlines", "arguments": {"image_path": "PATH"}}
14. get_malfind             — {"tool": "get_malfind", "arguments": {"image_path": "PATH"}}

EVIDENCE TABLES:
  Disk:   mft_events, prefetch_events, amcache_entries, evtx_events, registry_runkeys
  Memory: memory_processes, memory_network, memory_cmdlines, memory_injections

MANDATORY PROTOCOL — DISK IMAGE:
Step 1: start_investigation first
Step 2: Run ALL five collection tools (get_mft_timeline, get_amcache, get_prefetch, get_evtx_events, get_registry_runkeys)
Step 3: Use query_evidence to explore suspicious findings
Step 4: Use submit_claim for every finding — NEVER state a finding without proving it
Step 5: Call get_coverage_status then conclude_investigation

MANDATORY PROTOCOL — MEMORY IMAGE (.raw/.mem/.dmp):
Step 1: start_investigation first with case_type='memory_analysis'
Step 2: Run ALL four memory extraction tools: get_process_list, get_network_connections, get_cmdlines, and get_malfind.
Step 3: CRITICAL HUNTING CONSTRAINT: Advanced malware renames its processes to blend in (e.g., malicious binaries named 'svchost.exe' or 'lsass.exe'). Never state a memory dump is clean just because 'powershell.exe' or 'cmd.exe' are missing.
Step 4: You MUST read the tool output messages carefully. Use query_evidence and target any suspicious PIDs, unusual parent-child relationships (PPIDs), unlinked processes, or foreign outbound IP connections noted in the triage text.
Step 5: Prove every single anomaly you find using submit_claim before concluding.
Step 6: Call conclude_investigation.

SQL SYNTAX: strings need single quotes: executable_name = 'evil.exe' or LIKE '%evil%'

IMPORTANT: Output ONLY the JSON object. No explanation before or after it."""


# Largest tool result (in chars) we will ever feed back into the LLM context.
# Protects against Groq free-tier TPM / HTTP 413 even if a tool ignores its caps.
MAX_RESULT_CHARS = 6000


def strip_reasoning(text):
    """
    Remove model reasoning blocks before JSON parsing.

    Handles well-formed <think>...</think>, unclosed <think> (model was cut off
    mid-reasoning), and a few common variants (<reasoning>, <thinking>).
    """
    if not text:
        return ""
    # Closed blocks, any of the common tag names, non-greedy, across newlines.
    text = re.sub(r'<(think|thinking|reasoning)>.*?</\1>', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    # Unclosed opening tag → drop everything from the tag onward.
    text = re.sub(r'<(think|thinking|reasoning)>.*$', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    # Stray closing tag with no opener → drop everything before it.
    m = re.search(r'</(think|thinking|reasoning)>', text, flags=re.IGNORECASE)
    if m:
        text = text[m.end():]
    return text.strip()


def _truncate_result(result_str):
    """Hard cap on the tool-result string handed back to the LLM."""
    if result_str and len(result_str) > MAX_RESULT_CHARS:
        return (result_str[:MAX_RESULT_CHARS]
                + f"\n…[truncated {len(result_str) - MAX_RESULT_CHARS} chars; "
                  "use query_evidence with a tighter sql_filter/limit]")
    return result_str


def dispatch(tool_name, arguments):
    """Routes tool calls to SIFT-PROOF functions."""
    try:
        # ── Disk analysis tools ───────────────────────────────────────────────
        if tool_name == "start_investigation":
            result = sift.start_investigation(
                arguments.get("image_path", ""),
                arguments.get("case_type", "generic")
            )
        elif tool_name == "get_mft_timeline":
            result = sift.get_mft_timeline(arguments.get("image_path", ""))
        elif tool_name == "get_amcache":
            result = sift.get_amcache(arguments.get("image_path", ""))
        elif tool_name == "get_prefetch":
            result = sift.get_prefetch(arguments.get("image_path", ""))
        elif tool_name == "get_evtx_events":
            result = sift.get_evtx_events(
                arguments.get("image_path", ""),
                arguments.get("event_ids", None)
            )
        elif tool_name == "get_registry_runkeys":
            result = sift.get_registry_runkeys(arguments.get("image_path", ""))
        elif tool_name == "query_evidence":
            result = sift.query_evidence(
                arguments.get("table", ""),
                arguments.get("sql_filter", "1=1"),
                arguments.get("limit", 20)
            )
        elif tool_name == "submit_claim":
            result = sift.submit_claim(arguments)
        elif tool_name == "get_coverage_status":
            result = sift.get_coverage_status()
        elif tool_name == "conclude_investigation":
            result = sift.conclude_investigation(
                arguments.get("analyst_summary", "")
            )

        # ── Memory analysis tools ─────────────────────────────────────────────
        elif tool_name == "get_process_list":
            result = sift.get_process_list(arguments.get("image_path", ""))
        elif tool_name == "get_network_connections":
            result = sift.get_network_connections(arguments.get("image_path", ""))
        elif tool_name == "get_cmdlines":
            result = sift.get_cmdlines(arguments.get("image_path", ""))
        elif tool_name == "get_malfind":
            result = sift.get_malfind(arguments.get("image_path", ""))

        else:
            result = {"error": f"Unknown tool: {tool_name}"}

        return json.dumps(result, indent=2, default=str)

    except ValueError as e:
        return json.dumps({"error": str(e)}, default=str)
    except Exception as e:
        return json.dumps({"error": f"Tool error: {str(e)}"}, default=str)


def run_investigation(image_path, case_type="generic", max_iterations=30):
    """Runs a complete autonomous forensic investigation."""

    backend = get_backend_info()
    print(f"\n{'='*60}")
    print(f"SIFT-PROOF INVESTIGATION STARTING")
    print(f"Backend: {backend['backend']} ({backend['model']}) — {backend['cost']}")
    print(f"Image: {image_path}")
    print(f"Case type: {case_type}")
    print(f"{'='*60}\n")

    # ── Reboot-resistant resume check ─────────────────────────────────────────
    prior = load_progress(image_path=image_path)
    if prior:
        print(f"[RESUME] Checkpoint found — was at iteration {prior.get('iteration', 0)}, "
              f"coverage {prior.get('coverage', {}).get('coverage_percentage', 0)}%")
        print(f"[RESUME] Prior confirmed findings: {len(prior.get('findings', []))}")
        resume_note = (
            f"\n\nRESUME CONTEXT: You were previously at iteration {prior['iteration']}. "
            f"Coverage was {prior.get('coverage',{}).get('coverage_percentage',0)}%. "
            f"Confirmed finding IDs already recorded: {prior.get('findings',[])}. "
            f"Pending goal: {prior.get('pending_goals','continue investigation')}. "
            f"Do NOT repeat tools you already called. Continue from where you left off."
        )
    else:
        clear_progress()
        resume_note = ""

    # ── Start execution trace ──────────────────────────────────────────────────
    trace_start(image_path, case_type, str(backend))

    # ── Build initial conversation ─────────────────────────────────────────────
    messages = [
        {
            "role": "user",
            "content": (
                f"Begin a {case_type} investigation on image: {image_path}\n"
                f"Follow the mandatory protocol. Cover all artifact categories. "
                f"Prove every finding with submit_claim. "
                f"Start with start_investigation now."
                + resume_note
            )
        }
    ]

    iteration = 0
    final_report = None
    consecutive_parse_failures = 0

    while iteration < max_iterations:
        iteration += 1
        trace_iteration(iteration, max_iterations)
        print(f"\n[AGENT] Iteration {iteration}/{max_iterations}")

        # ── Call the LLM ───────────────────────────────────────────────────────
        try:
            response_text = chat(messages, SYSTEM_PROMPT)
        except Exception as e:
            print(f"[AGENT] LLM error: {e}")
            break

        # Strip reasoning blocks (Qwen, DeepSeek, etc.) before any JSON parsing
        response_text = strip_reasoning(response_text)

        print(f"[AGENT] Raw response: {response_text[:200] if response_text else 'empty'}")

        # ── Trace LLM response ────────────────────────────────────────────────
        trace_llm_response(response_text, 1)

        # ── Parse the JSON tool call ───────────────────────────────────────────
        tool_call = parse_tool_call(response_text)

        if tool_call is None:
            consecutive_parse_failures += 1
            print(f"[AGENT] Could not parse tool call (failure {consecutive_parse_failures})")

            if consecutive_parse_failures >= 3:
                print("[AGENT] Too many parse failures. Stopping.")
                break

            messages.append({"role": "assistant", "content": response_text or ""})
            messages.append({
                "role": "user",
                "content": (
                    "Your response was not valid JSON. "
                    "You must output ONLY a JSON object like: "
                    '{"tool": "TOOL_NAME", "arguments": {...}}\n'
                    "Try again. What is your next tool call?"
                )
            })
            # Save progress even on parse failures
            _save_state(iteration, image_path, case_type,
                        f"parse failure {consecutive_parse_failures}, retrying")
            continue

        consecutive_parse_failures = 0
        tool_name  = tool_call.get("tool", "")
        arguments  = tool_call.get("arguments", {})

        # ── Check if investigation is done ────────────────────────────────────
        if tool_name == "DONE":
            summary = arguments.get("summary", "Investigation completed.")
            print(f"\n{'='*60}")
            print("INVESTIGATION COMPLETE")
            print(f"Summary: {summary[:300]}")
            print(f"{'='*60}")
            final_report = {"status": "COMPLETE", "summary": summary}
            mark_complete()
            trace_end("COMPLETE_DONE", 0, 0)
            break

        print(f"[AGENT] → {tool_name}({json.dumps(arguments, default=str)[:100]})")

        # ── Trace before tool execution ───────────────────────────────────────
        trace_tool_call(tool_name, arguments)

        # ── Execute the tool ───────────────────────────────────────────────────
        result_str = dispatch(tool_name, arguments)
        result_preview = result_str[:400] + "..." if len(result_str) > 400 else result_str
        print(f"[AGENT] ← {result_preview}")

        # ── Extract finding_id from result if present ─────────────────────────
        finding_id = None
        try:
            parsed_result = json.loads(result_str)
            finding_id = parsed_result.get("finding_id")
        except Exception:
            pass

        # ── Trace after tool execution ────────────────────────────────────────
        trace_tool_result(tool_name, result_str, finding_id)

        # ── Check if conclude_investigation succeeded ─────────────────────────
        if tool_name == "conclude_investigation":
            try:
                result_data = json.loads(result_str)
                if result_data.get("status") == "COMPLETE":
                    total_f = result_data.get('total_findings', 0)
                    cov_pct = result_data.get('coverage', {}).get('coverage_percentage', 0)
                    print(f"\n{'='*60}")
                    print(f"INVESTIGATION COMPLETE")
                    print(f"Total findings: {total_f}")
                    print(f"Coverage: {cov_pct}%")
                    print(f"{'='*60}")
                    mark_complete()
                    trace_end("COMPLETE", total_f, cov_pct)
                    return result_data
            except json.JSONDecodeError:
                pass

        # ── Save progress checkpoint after every iteration ────────────────────
        _save_state(iteration, image_path, case_type,
                    f"completed tool {tool_name}, continuing")

        # ── Add exchange to conversation history (capped to protect context) ──
        messages.append({"role": "assistant", "content": response_text})
        messages.append({
            "role": "user",
            "content": (f"Tool '{tool_name}' result:\n{_truncate_result(result_str)}\n\n"
                        f"What is your next tool call? Output JSON only.")
        })

    print(f"\n[AGENT] Finished after {iteration} iterations.")
    trace_end("INCOMPLETE", 0, 0)
    return final_report or {"status": "INCOMPLETE", "iterations": iteration}


def _save_state(iteration, image_path, case_type, pending_goals):
    """Save checkpoint — called after every iteration."""
    try:
        coverage_snap = sift.get_coverage_status()
    except Exception:
        coverage_snap = {}
    try:
        raw_findings = execute_safe_query(
            "SELECT finding_id FROM confirmed_findings"
        )
        findings_list = [r.get('finding_id', '') for r in raw_findings]
    except Exception:
        findings_list = []

    save_progress(
        iteration=iteration,
        findings=findings_list,
        coverage=coverage_snap,
        pending_goals=pending_goals,
        image_path=image_path,
        case_type=case_type
    )


# ── Runtime gateway ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SIFT-PROOF Autonomous Investigation Agent"
    )
    parser.add_argument(
        "--image",
        type=str,
        default="/media/sf_win7-64-nfury-10.3.58.6/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01",
        help="Absolute path to the forensic target (disk image or memory dump)"
    )
    parser.add_argument(
        "--type",
        type=str,
        default="windows_compromise",
        choices=["windows_compromise", "ransomware", "generic", "memory_analysis"],
        help="Investigation case type"
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore any saved checkpoint and start fresh"
    )

    args = parser.parse_args()

    if args.fresh:
        clear_progress()
        print("[PROGRESS] Fresh start — checkpoint cleared.")

    run_investigation(image_path=args.image, case_type=args.type)