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
2.  get_mft_timeline        — {"tool": "get_mft_timeline", "arguments": {"image_path": "PATH"}}
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
 
═══════════════════════════════════════════════════════════
MANDATORY PROTOCOL — DISK IMAGE
═══════════════════════════════════════════════════════════
 
Step 1: start_investigation first.
 
Step 2: Run ALL five collection tools:
  get_mft_timeline, get_amcache, get_prefetch, get_evtx_events, get_registry_runkeys
 
Step 3: SMART TRIAGE — read the MFT results carefully BEFORE filtering.
  First: query_evidence(mft_events, "1=1", limit=20) to understand what kind of
  system this is. Look for clues:
    - XAMPP, Apache, IIS, nginx → web server — shift to web compromise hunting
    - SQL Server, MySQL → database server — look for SQL injection artifacts
    - Standard Windows desktop → traditional malware hunting
 
Step 4: HUNT BY SYSTEM TYPE — do not just search for .exe in AppData.
 
  IF web server indicators found (xampp, htdocs, wwwroot, inetpub, apache):
    ► Search for web shells: query_evidence(mft_events,
      "full_path LIKE '%htdocs%' OR full_path LIKE '%wwwroot%' OR
       full_path LIKE '%inetpub%'", limit=50)
    ► Look for script files: LIKE '%.php' OR LIKE '%.asp' OR LIKE '%.aspx'
      OR LIKE '%.jsp' that were recently created or modified
    ► Suspicious web shell patterns: single-file .php in web directory,
      very small file size, created outside business hours
    ► Check for command execution: filenames like 'cmd.php', 'shell.php',
      'c99.php', 'r57.php', 'webshell.asp', or any .php with unusual names
    ► Look in temp paths: LIKE '%/tmp/%' OR LIKE '%\\Temp\\%' for downloaded tools
 
  IF standard Windows desktop:
    ► Search AppData: LIKE '%AppData%' AND filename LIKE '%.exe'
    ► Search Recycle Bin: LIKE '%Recycle%' AND filename LIKE '%.exe'
    ► Check scheduled tasks in MFT: LIKE '%Tasks%' AND LIKE '%.job'
 
  ALWAYS search for these regardless of system type:
    ► Large files in unexpected locations (file_size > 5000000)
    ► Files with mismatched extensions (.txt that is huge, .jpg that is .exe)
    ► Recently created executables anywhere: filename LIKE '%.exe' with
      created_at in the incident timeframe
 
Step 5: Use submit_claim for every finding. NEVER declare clean without proving it.
  If 0 results on a filter, try BROADER filters, not narrower ones.
  Do NOT conclude just because event_id=4688 returned 0 rows.
 
Step 6: Check registry for persistence pointing to web paths:
  value_data LIKE '%xampp%' OR value_data LIKE '%htdocs%' OR value_data LIKE '%php%'
 
Step 7: Call get_coverage_status. When is_complete=true, call conclude_investigation
  with full analyst summary including what the system was and what type of
  compromise was found.
 
═══════════════════════════════════════════════════════════
MANDATORY PROTOCOL — MEMORY IMAGE (.raw/.mem/.dmp)
═══════════════════════════════════════════════════════════
 
Step 1: start_investigation with case_type='memory_analysis'
Step 2: Run ALL four memory tools: get_process_list, get_network_connections,
        get_cmdlines, get_malfind
Step 3: CRITICAL — Malware renames itself. Never conclude clean just because
        powershell.exe or cmd.exe are absent.
Step 4: Hunt anomalies:
  - svchost.exe with ppid NOT equal to services.exe PID (process injection)
  - svchost.exe with thread count > 200 (anomalous)
  - Any process with established connection to non-RFC1918 IP
  - Processes with no create_time (hollowed/injected)
  - Apache/nginx/IIS processes with outbound connections (webshell C2)
Step 5: Prove every anomaly with submit_claim before concluding.
Step 6: Call conclude_investigation.
 
═══════════════════════════════════════════════════════════
SQL RULES
═══════════════════════════════════════════════════════════
- Strings need single quotes: filename = 'evil.php' or LIKE '%shell%'
- Case-insensitive: UPPER(filename) LIKE '%SHELL%'
- Do NOT put LIMIT inside sql_filter — use the limit parameter instead
- Paths use forward slash in the DB: full_path LIKE '%/htdocs/%'
 
IMPORTANT: Output ONLY the JSON object. No explanation before or after it."""

# Largest tool result (in chars) we will ever feed back into the LLM context.
MAX_RESULT_CHARS = 6000


def strip_reasoning(text):
    """
    Remove model reasoning blocks before JSON parsing.
    Handles <think>, <thinking>, <reasoning> — closed and unclosed.
    """
    if not text:
        return ""
    text = re.sub(r'<(think|thinking|reasoning)>.*?</\1>', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<(think|thinking|reasoning)>.*$', '', text,
                  flags=re.DOTALL | re.IGNORECASE)
    m = re.search(r'</(think|thinking|reasoning)>', text, flags=re.IGNORECASE)
    if m:
        text = text[m.end():]
    return text.strip()


def _extract_first_json(text):
    """
    FIX: Some models output two JSON objects back-to-back in one response.
    parse_tool_call sees invalid JSON and returns None.
    This function extracts just the FIRST complete JSON object.
    Nothing else in the file is touched — this is purely additive.
    """
    if not text:
        return None
    first = text.find('{')
    if first == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[first:], first):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[first:i + 1])
                except Exception:
                    return None
    return None


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


def run_investigation(image_path, case_type="generic", max_iterations=35):
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

        # FIX: model sometimes outputs two JSON objects in one response.
        # parse_tool_call sees invalid JSON and returns None.
        # _extract_first_json pulls out just the first valid object.
        if tool_call is None and response_text:
            tool_call = _extract_first_json(response_text)
            if tool_call is not None:
                print(f"[AGENT] Recovered first JSON object from multi-object response")

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

        # FIX: when coverage hits 100%, force the next message to conclude.
        # Without this, the agent keeps querying evidence until it hits max_iterations.
        if tool_name == "get_coverage_status":
            try:
                cov_data = json.loads(result_str)
                if cov_data.get("is_complete") and cov_data.get("coverage_percentage") == 100:
                    messages.append({"role": "assistant", "content": response_text})
                    messages.append({
                        "role": "user",
                        "content": (
                            f"Tool 'get_coverage_status' result:\n"
                            f"{_truncate_result(result_str)}\n\n"
                            "Coverage is 100% complete. All mandatory categories covered. "
                            "You MUST call conclude_investigation RIGHT NOW with your full "
                            "analyst summary of everything you found. "
                            "Do not call any other tool first. Output the JSON now."
                        )
                    })
                    continue
            except Exception:
                pass

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