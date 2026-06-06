
 
import os
import sys
import re
 
ROOT = os.path.dirname(os.path.abspath(__file__))
errors = []
 
 
def patch_file(path, find_str, replace_str, label):
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        errors.append(f"  ✗ {label}: file not found — {path}")
        return False
    with open(full, 'r') as f:
        content = f.read()
    if find_str not in content:
        errors.append(f"  ✗ {label}: target string not found in {path}")
        return False
    with open(full, 'w') as f:
        f.write(content.replace(find_str, replace_str, 1))
    print(f"  ✓ {label}")
    return True
 
 
def append_if_missing(path, marker, block, label):
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        errors.append(f"  ✗ {label}: file not found — {path}")
        return False
    with open(full, 'r') as f:
        content = f.read()
    if marker in content:
        print(f"  ✓ {label} (already applied)")
        return True
    with open(full, 'a') as f:
        f.write('\n' + block + '\n')
    print(f"  ✓ {label}")
    return True
 
 
# ─────────────────────────────────────────────────────────────
# FIX 1 — query_evidence: add memory tables to valid_tables
# ─────────────────────────────────────────────────────────────
print("\n[FIX 1] Adding memory tables to query_evidence whitelist...")
 
OLD_TABLES = """    valid_tables = [
        'mft_events', 'prefetch_events', 'amcache_entries',
        'evtx_events', 'registry_runkeys', 'confirmed_findings'
    ]"""
 
NEW_TABLES = """    valid_tables = [
        'mft_events', 'prefetch_events', 'amcache_entries',
        'evtx_events', 'registry_runkeys', 'confirmed_findings',
        'memory_processes', 'memory_network',
        'memory_cmdlines',  'memory_injections'
    ]"""
 
patch_file("mcp_server/functions.py", OLD_TABLES, NEW_TABLES,
           "query_evidence valid_tables")
 
 
# ─────────────────────────────────────────────────────────────
# FIX 2 — coverage.py: add memory_analysis case type
# ─────────────────────────────────────────────────────────────
print("\n[FIX 2] Adding memory_analysis coverage type...")
 
MEMORY_COVERAGE_BLOCK = '''
# ── Memory analysis coverage type (added by apply_memory_fixes.py) ────────────
_MEMORY_MANDATORY = [
    "process_analysis",
    "injection_detection",
    "command_history"
]
 
_MEMORY_OPTIONAL = [
    "network_analysis"
]
 
_MEMORY_TOOL_MAP = {
    "get_process_list":        "process_analysis",
    "get_malfind":             "injection_detection",
    "get_cmdlines":            "command_history",
    "get_network_connections": "network_analysis"
}
 
def _patch_memory_coverage():
    """Inject memory_analysis into whatever case-type registry exists."""
    import sys as _sys
    mod = _sys.modules.get("core.coverage") or _sys.modules.get("coverage")
    if mod is None:
        return
 
    # Try dict-based registry (most common pattern)
    for attr in ("COVERAGE_CATEGORIES", "CASE_TYPES", "COVERAGE_MAP",
                 "_coverage_map", "case_coverage"):
        registry = getattr(mod, attr, None)
        if isinstance(registry, dict):
            if "memory_analysis" not in registry:
                registry["memory_analysis"] = {
                    "mandatory": _MEMORY_MANDATORY,
                    "optional":  _MEMORY_OPTIONAL,
                    "tool_map":  _MEMORY_TOOL_MAP
                }
                print("[COVERAGE] memory_analysis case type registered.")
            return
 
    # Try function-based initializer — monkey-patch initialize_coverage
    _orig_init = getattr(mod, "initialize_coverage", None)
    if _orig_init:
        def _patched_init(case_type="generic", *a, **kw):
            if case_type == "memory_analysis":
                # Build a minimal coverage state for memory
                state = {
                    "case_type":          "memory_analysis",
                    "mandatory_covered":  [],
                    "mandatory_missing":  list(_MEMORY_MANDATORY),
                    "optional_covered":   [],
                    "tools_called":       [],
                    "is_complete":        False,
                    "coverage_percentage": 0
                }
                try:
                    from core.coverage import _store_coverage_state
                    _store_coverage_state(state)
                except Exception:
                    pass
                print(f"[COVERAGE] Initialized: memory_analysis")
                print(f"[COVERAGE] Mandatory: {_MEMORY_MANDATORY}")
                return state
            return _orig_init(case_type, *a, **kw)
        mod.initialize_coverage = _patched_init
 
    # Also patch record_tool_call to understand memory tools
    _orig_record = getattr(mod, "record_tool_call", None)
    if _orig_record:
        def _patched_record(tool_name, *a, **kw):
            category = _MEMORY_TOOL_MAP.get(tool_name)
            if category:
                print(f"[COVERAGE] ✓ Covered: {category}")
            return _orig_record(tool_name, *a, **kw)
        mod.record_tool_call = _patched_record
 
_patch_memory_coverage()
'''
 
append_if_missing(
    "core/coverage.py",
    "memory_analysis",
    MEMORY_COVERAGE_BLOCK,
    "memory_analysis coverage type"
)
 
 
# ─────────────────────────────────────────────────────────────
# FIX 3 — volatility_parser.py: netscan timeout 600 → 1200
# ─────────────────────────────────────────────────────────────
print("\n[FIX 3] Increasing netscan timeout from 600s to 1200s...")
 
patch_file(
    "tools/volatility_parser.py",
    "raw, err = _run_vol(image_path, 'windows.netscan')",
    "raw, err = _run_vol(image_path, 'windows.netscan', timeout=1200)",
    "netscan timeout"
)
 
 
# ─────────────────────────────────────────────────────────────
# FIX 4 — run_investigation.py: auto-detect memory image type
# ─────────────────────────────────────────────────────────────
print("\n[FIX 4] Adding memory image auto-detection to run_investigation.py...")
 
MEMORY_DETECTION = '''
    # Auto-detect memory image — override case_type if extension is .raw/.mem/.dmp
    mem_extensions = ('.raw', '.mem', '.dmp', '.vmem', '.lime')
    if any(args.image.lower().endswith(ext) for ext in mem_extensions):
        if args.type == "windows_compromise":
            print(f"[AUTO] Detected memory image ({args.image.split(\\'.\\')[-1]}) — switching to memory_analysis mode")
            args.type = "memory_analysis"
'''
 
OLD_GATEWAY = "    run_investigation(image_path=args.image, case_type=args.type)"
NEW_GATEWAY  = MEMORY_DETECTION + "\n    run_investigation(image_path=args.image, case_type=args.type)"
 
patch_file("run_investigation.py", OLD_GATEWAY, NEW_GATEWAY,
           "memory auto-detection in run_investigation.py")
 
 
# ─────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────
print("\n" + "="*55)
if not errors:
    print("✅  ALL 4 FIXES APPLIED SUCCESSFULLY")
    print("="*55)
    print("\nNext commands:")
    print('  MEM="/media/sf_HACKATHON-2026/HACKATHON-2026/Standard Forensic Case/Rocba-Memory/Rocba-Memory/Rocba-Memory/Rocba-Memory.raw"')
    print('  python3 run_investigation.py --image "$MEM" --fresh')
    print("\nExpected behaviour:")
    print("  [AUTO] Detected memory image (raw) — switching to memory_analysis mode")
    print("  Iterations 2-5: Volatility extracts 2186 processes, cmdlines, injections")
    print("  Iterations 6+:  Agent queries memory_processes, memory_cmdlines,")
    print("                  memory_injections — NO 'Invalid table' errors")
    print("  Finds: PAGE_EXECUTE_READWRITE injections, suspicious cmdlines")
    print("  Coverage 100% → conclude_investigation")
else:
    print(f"⚠️  {len(errors)} fix(es) could not be applied:")
    for e in errors:
        print(e)
    print("\nApply these manually (see messages above for which files to edit).")
    print("="*55)