
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.database import execute_safe_query

SEP = "="*65

def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)

def show(rows, cols=None, limit=20):
    if not rows:
        print("  → No results found.")
        return
    for r in rows[:limit]:
        if cols:
            line = " | ".join(str(r.get(c, "")) for c in cols)
        else:
            line = json.dumps(r, default=str)[:120]
        print(f"  • {line}")
    if len(rows) > limit:
        print(f"  ... and {len(rows)-limit} more")

# ── Q1: Which projects / sensitive files did Fred access? ─────────────────────
section("Q1 — SENSITIVE FILES ACCESSED BY FRED (Documents, Projects, IP)")
q1 = execute_safe_query("""
    SELECT filename, full_path, accessed_at, modified_at, file_size
    FROM mft_events
    WHERE (full_path LIKE '%/Users/fredr/%' OR full_path LIKE '%/Users/Fred%')
    AND (
        filename LIKE '%.docx' OR filename LIKE '%.xlsx' OR
        filename LIKE '%.pdf'  OR filename LIKE '%.pptx' OR
        filename LIKE '%.zip'  OR filename LIKE '%.rar'  OR
        filename LIKE '%.7z'   OR filename LIKE '%.tar'  OR
        filename LIKE '%.csv'  OR filename LIKE '%.mdb'  OR
        filename LIKE '%.sql'  OR filename LIKE '%.bak'
    )
    ORDER BY accessed_at DESC
""")
show(q1, ['filename', 'full_path', 'accessed_at', 'file_size'])
print(f"\n  TOTAL: {len(q1)} sensitive documents in Fred's profile")

# ── Q2: Data staging — large files created/moved ─────────────────────────────
section("Q2 — DATA STAGING: Large files (>1MB) in Fred's directories")
q2 = execute_safe_query("""
    SELECT filename, full_path, created_at, modified_at, file_size
    FROM mft_events
    WHERE (full_path LIKE '%/Users/fredr/%' OR full_path LIKE '%/Users/Fred%')
    AND file_size > 1000000
    ORDER BY created_at DESC
""")
show(q2, ['filename', 'full_path', 'created_at', 'file_size'])
print(f"\n  TOTAL: {len(q2)} large files in user directories")

# ── Q3: Cloud sync / exfiltration tools ──────────────────────────────────────
section("Q3 — EXFILTRATION VECTOR: Cloud sync / transfer tools")
q3_cloud = execute_safe_query("""
    SELECT filename, full_path, modified_at, file_size
    FROM mft_events
    WHERE full_path LIKE '%OneDrive%'
    OR full_path LIKE '%Dropbox%'
    OR full_path LIKE '%Google Drive%'
    OR full_path LIKE '%DriveFS%'
    OR full_path LIKE '%SharePoint%'
    ORDER BY modified_at DESC
""")
print(f"\n  Cloud sync artifacts: {len(q3_cloud)}")
show(q3_cloud, ['filename', 'full_path', 'modified_at', 'file_size'], limit=15)

q3_tools = execute_safe_query("""
    SELECT executable_name, last_run_time, run_count
    FROM prefetch_events
    WHERE UPPER(executable_name) LIKE '%FTP%'
    OR UPPER(executable_name) LIKE '%WINSCP%'
    OR UPPER(executable_name) LIKE '%FILEZILLA%'
    OR UPPER(executable_name) LIKE '%PUTTY%'
    OR UPPER(executable_name) LIKE '%ROBOCOPY%'
    OR UPPER(executable_name) LIKE '%XCOPY%'
    OR UPPER(executable_name) LIKE '%7Z%'
    OR UPPER(executable_name) LIKE '%WINRAR%'
    OR UPPER(executable_name) LIKE '%RCLONE%'
    OR UPPER(executable_name) LIKE '%CURL%'
    OR UPPER(executable_name) LIKE '%WGET%'
""")
print(f"\n  Transfer tools in prefetch: {len(q3_tools)}")
show(q3_tools, ['executable_name', 'last_run_time', 'run_count'])

# ── Q4: USB / removable media ─────────────────────────────────────────────────
section("Q4 — EXFILTRATION VECTOR: USB / Removable Media Evidence")
q4_usb = execute_safe_query("""
    SELECT filename, full_path, created_at
    FROM mft_events
    WHERE full_path LIKE '%/System Volume Information/%'
    OR full_path LIKE '%USBSTOR%'
    OR full_path LIKE '%RemovableMedia%'
    ORDER BY created_at DESC
""")
print(f"  System Volume Info entries (USB signature): {len(q4_usb)}")
show(q4_usb, ['filename', 'full_path', 'created_at'])

# Check recycle bin for deleted evidence
q4_recycle = execute_safe_query("""
    SELECT filename, full_path, modified_at, file_size
    FROM mft_events
    WHERE full_path LIKE '%$Recycle%' OR full_path LIKE '%RECYCLE%'
    ORDER BY modified_at DESC
""")
print(f"\n  Recycle Bin artifacts: {len(q4_recycle)}")
show(q4_recycle, ['filename', 'full_path', 'modified_at', 'file_size'])

# ── Q5: Timeline — when did suspicious activity occur? ───────────────────────
section("Q5 — TIMELINE: Activity around November 2020 (image date)")
q5 = execute_safe_query("""
    SELECT filename, full_path, created_at, modified_at, file_size
    FROM mft_events
    WHERE (full_path LIKE '%/Users/fredr/%' OR full_path LIKE '%/Users/Fred%')
    AND (created_at >= '2020-11-01' OR modified_at >= '2020-11-01')
    ORDER BY created_at DESC
""")
print(f"  Files created/modified in November 2020: {len(q5)}")
show(q5, ['filename', 'full_path', 'created_at', 'file_size'])

# ── Q6: Suspicious executables run by Fred ───────────────────────────────────
section("Q6 — EXECUTION: Suspicious programs Fred ran (Prefetch)")
q6 = execute_safe_query("""
    SELECT executable_name, last_run_time, run_count
    FROM prefetch_events
    WHERE UPPER(executable_name) NOT LIKE '%WINDOWS%'
    AND UPPER(executable_name) NOT LIKE '%MICROSOFT%'
    AND UPPER(executable_name) NOT LIKE '%OFFICE%'
    AND UPPER(executable_name) NOT LIKE '%CHROME%'
    AND UPPER(executable_name) NOT LIKE '%ONEDRIVE%'
    ORDER BY last_run_time DESC
""")
print(f"  Non-standard executions: {len(q6)}")
show(q6, ['executable_name', 'last_run_time', 'run_count'])

# ── Q7: Email / Outlook artifacts ────────────────────────────────────────────
section("Q7 — EXFILTRATION: Email artifacts (Outlook PST/OST)")
q7 = execute_safe_query("""
    SELECT filename, full_path, modified_at, file_size
    FROM mft_events
    WHERE filename LIKE '%.pst' OR filename LIKE '%.ost'
    OR filename LIKE '%.msg' OR filename LIKE '%.eml'
    ORDER BY modified_at DESC
""")
print(f"  Email archive files: {len(q7)}")
show(q7, ['filename', 'full_path', 'modified_at', 'file_size'])

# ── SUMMARY ───────────────────────────────────────────────────────────────────
section("SUMMARY — KEY LEADS FOR ROCBA INVESTIGATION")
print("""
  Run python3 replay.py --all to see SQL-confirmed findings.
  NEXT STEPS for deeper analysis:
  1. Any .zip/.rar files in Fred's profile → likely staged data
  2. OneDrive sync folder → check for sensitive docs uploaded
  3. USB System Volume Info → proves removable media connected
  4. Prefetch transfer tools → proves what Fred ran to exfiltrate
  5. Cross-correlate with memory findings:
     - APSDaemon.exe → 17.57.144.165 (Apple server, may be legitimate)
     - svchost.exe 266 threads → investigate further on disk
  To prove any of these: run submit_claim against the evidence tables above.
""")
