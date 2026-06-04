

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agent.llm_client import chat, parse_tool_call, get_backend_info
import mcp_server.functions as sift


SYSTEM_PROMPT = """You are SIFT-PROOF, an autonomous digital forensic analyst.

You investigate disk images for evidence of malicious activity.
You communicate ONLY by outputting a single JSON object per response.

OUTPUT FORMAT — you must always output exactly one JSON object:
{"tool": "TOOL_NAME", "arguments": {"param": "value"}}

To finish the investigation:
{"tool": "DONE", "arguments": {"summary": "your full analysis here"}}

AVAILABLE TOOLS:
1. start_investigation — {"tool": "start_investigation", "arguments": {"image_path": "PATH", "case_type": "windows_compromise"}}
2. get_mft_timeline — {"tool": "get_mft_timeline", "arguments": {"image_path": "PATH"}}
3. get_amcache — {"tool": "get_amcache", "arguments": {"image_path": "PATH"}}
4. get_prefetch — {"tool": "get_prefetch", "arguments": {"image_path": "PATH"}}
5. get_evtx_events — {"tool": "get_evtx_events", "arguments": {"image_path": "PATH"}}
6. get_registry_runkeys — {"tool": "get_registry_runkeys", "arguments": {"image_path": "PATH"}}
7. query_evidence — {"tool": "query_evidence", "arguments": {"table": "TABLE", "sql_filter": "FILTER", "limit": 20}}
8. submit_claim — {"tool": "submit_claim", "arguments": {"claim": "TEXT", "evidence_table": "TABLE", "sql_filter": "FILTER", "expected_result": "at_least_one_row", "mitre_technique": "TXXXX"}}
9. get_coverage_status — {"tool": "get_coverage_status", "arguments": {}}
10. conclude_investigation — {"tool": "conclude_investigation", "arguments": {"analyst_summary": "FULL SUMMARY"}}

MANDATORY PROTOCOL:
Step 1: start_investigation first
Step 2: Run ALL five collection tools (get_mft_timeline, get_amcache, get_prefetch, get_evtx_events, get_registry_runkeys)
Step 3: Use query_evidence to explore suspicious findings
Step 4: Use submit_claim for every finding — NEVER state a finding without proving it
Step 5: If submit_claim returns ASSERTION_FAILED read the real data and revise
Step 6: If submit_claim returns TEMPORAL_CONTRADICTION that is high value evidence
Step 7: Call get_coverage_status then conclude_investigation

SQL SYNTAX: strings need single quotes: executable_name = 'evil.exe' or LIKE '%evil%'

IMPORTANT: Output ONLY the JSON object. No explanation before or after it."""


def dispatch(tool_name, arguments):
    """Calls the appropriate SIFT-PROOF function."""
    try:
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
        else:
            result = {"error": f"Unknown tool: {tool_name}"}

        return json.dumps(result, indent=2, default=str)

    except ValueError as e:
        return json.dumps({"error": str(e)}, default=str)
    except Exception as e:
        return json.dumps({"error": f"Tool error: {str(e)}"}, default=str)


def run_investigation(image_path, case_type="generic", max_iterations=30):
    """Runs a complete forensic investigation."""

    backend = get_backend_info()
    print(f"\n{'='*60}")
    print(f"SIFT-PROOF INVESTIGATION STARTING")
    print(f"Backend: {backend['backend']} ({backend['model']}) — {backend['cost']}")
    print(f"Image: {image_path}")
    print(f"Case type: {case_type}")
    print(f"{'='*60}\n")

    # Conversation history — plain text, no tool call objects
    messages = [
        {
            "role": "user",
            "content": (
                f"Begin a {case_type} investigation on image: {image_path}\n"
                f"Follow the mandatory protocol. Cover all artifact categories. "
                f"Prove every finding with submit_claim. "
                f"Start with start_investigation now."
            )
        }
    ]

    iteration = 0
    final_report = None
    consecutive_parse_failures = 0

    while iteration < max_iterations:
        iteration += 1
        print(f"\n[AGENT] Iteration {iteration}/{max_iterations}")

        try:
            response_text = chat(messages, SYSTEM_PROMPT)
        except Exception as e:
            print(f"[AGENT] LLM error: {e}")
            break

        print(f"[AGENT] Raw response: {response_text[:200] if response_text else 'empty'}")

        # Parse the JSON tool call from response
        tool_call = parse_tool_call(response_text)

        if tool_call is None:
            consecutive_parse_failures += 1
            print(f"[AGENT] Could not parse tool call (failure {consecutive_parse_failures})")

            if consecutive_parse_failures >= 3:
                print("[AGENT] Too many parse failures. Stopping.")
                break

            # Ask the model to try again with a reminder
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
            continue

        consecutive_parse_failures = 0
        tool_name = tool_call.get("tool", "")
        arguments = tool_call.get("arguments", {})

        # Check if investigation is done
        if tool_name == "DONE":
            summary = arguments.get("summary", "Investigation completed.")
            print(f"\n{'='*60}")
            print("INVESTIGATION COMPLETE")
            print(f"Summary: {summary[:300]}")
            print(f"{'='*60}")
            final_report = {"status": "COMPLETE", "summary": summary}
            break

        print(f"[AGENT] → {tool_name}({json.dumps(arguments, default=str)[:100]})")

        # Execute the tool
        result_str = dispatch(tool_name, arguments)
        result_preview = result_str[:400] + "..." if len(result_str) > 400 else result_str
        print(f"[AGENT] ← {result_preview}")

        # Check if conclude_investigation succeeded
        if tool_name == "conclude_investigation":
            try:
                result_data = json.loads(result_str)
                if result_data.get("status") == "COMPLETE":
                    print(f"\n{'='*60}")
                    print(f"INVESTIGATION COMPLETE")
                    print(f"Total findings: {result_data.get('total_findings', 0)}")
                    cov = result_data.get('coverage', {})
                    print(f"Coverage: {cov.get('coverage_percentage', 0)}%")
                    print(f"{'='*60}")
                    return result_data
            except json.JSONDecodeError:
                pass

        # Add this exchange to conversation history
        messages.append({"role": "assistant", "content": response_text})
        messages.append({
            "role": "user",
            "content": (
                f"Tool '{tool_name}' result:\n{result_str}\n\n"
                f"What is your next tool call? Output JSON only."
            )
        })

    print(f"\n[AGENT] Finished after {iteration} iterations.")
    return final_report or {"status": "INCOMPLETE", "iterations": iteration}

