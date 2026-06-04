

import argparse, json, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from core.database import execute_safe_query, initialize_database
from core.ledger import read_all


def replay(fid):
    initialize_database()
    print(f"\n{'='*65}")
    print(f"SIFT-PROOF FINDING REPLAY — ID: {fid}")
    print(f"{'='*65}\n")

    findings = execute_safe_query(
        f"SELECT * FROM confirmed_findings WHERE finding_id = '{fid}'"
    )
    if not findings:
        print(f"Finding '{fid}' not found.")
        all_f = execute_safe_query("SELECT finding_id, claim FROM confirmed_findings")
        print("Available findings:")
        for f in all_f:
            print(f"  {f['finding_id']}: {f['claim'][:55]}...")
        return

    f = findings[0]
    print(f"📋 CLAIM:      {f['claim']}")
    print(f"🔬 CONFIDENCE: {f['confidence_tier']}")
    print(f"🛡️  TEMPORAL:  {f['temporal_check']}")
    print(f"⚔️  MITRE:     {f['mitre_technique']}")
    print(f"\n📊 SQL PROOF:")
    print(f"   {f['sql_executed']}")
    print(f"\n🔗 CHAIN OF CUSTODY:")
    print(f"   SHA256: {f['sha256_of_evidence']}")

    rows = execute_safe_query(f['sql_executed'])
    print(f"\n🔄 RE-EXECUTING SQL NOW...")
    print(f"   Original: {f['rows_matched']} rows | Current: {len(rows)} rows")

    if f['rows_matched'] == len(rows):
        print(f"   ✅ VERIFIED — Evidence unchanged")
    else:
        print(f"   ⚠️  Row count changed since proof recorded")

    if rows:
        print(f"\n📁 MATCHING EVIDENCE (first 3 rows):")
        for i, row in enumerate(rows[:3], 1):
            print(f"\n   Row {i}:")
            for k, v in row.items():
                if k != 'sha256_of_raw_output':
                    print(f"     {k}: {v}")

    print(f"\n{'='*65}")


def show_all():
    initialize_database()
    findings = execute_safe_query(
        "SELECT finding_id, confidence_tier, claim, mitre_technique FROM confirmed_findings"
    )
    if not findings:
        print("No confirmed findings in database.")
        print("Run: python3 run_investigation.py --demo")
        return

    confirmed = [f for f in findings if f['confidence_tier'] == 'CONFIRMED']
    inferred = [f for f in findings if f['confidence_tier'] == 'INFERRED']

    print(f"\n{'='*65}")
    print(f"SIFT-PROOF — ALL CONFIRMED FINDINGS")
    print(f"{'='*65}")
    print(f"Total: {len(findings)} | ✅ CONFIRMED: {len(confirmed)} | 🔶 INFERRED: {len(inferred)}\n")

    for f in findings:
        icon = "✅" if f['confidence_tier'] == 'CONFIRMED' else "🔶"
        print(f"{icon} [{f['finding_id']}] {f['claim'][:55]}...")
        print(f"     {f['confidence_tier']} | {f['mitre_technique']}\n")

    print(f"Replay any finding: python3 replay.py --finding_id <ID>")


def show_audit():
    entries = read_all()
    print(f"\n{'='*65}")
    print(f"SIFT-PROOF — COMPLETE AUDIT TRAIL ({len(entries)} entries)")
    print(f"{'='*65}\n")
    for e in entries:
        t = e.get('type', '')
        ts = e.get('timestamp', '')[:19]
        if t == 'start':
            print(f"🔍 [{ts}] INVESTIGATION STARTED — {e.get('case',{}).get('image_path','')}")
        elif t == 'tool_call':
            print(f"🔧 [{ts}] TOOL: {e.get('tool','')} — {e.get('result_summary',{}).get('rows_inserted',0)} rows")
        elif t == 'assertion':
            r = e.get('result', '')
            icon = "✅" if r == "CONFIRMED" else ("⚠️" if "TEMPORAL" in r else "❌")
            print(f"{icon} [{ts}] {r} — {str(e.get('claim',''))[:50]}...")
        elif t == 'complete':
            print(f"🏁 [{ts}] COMPLETE — {e.get('summary',{}).get('total_findings',0)} findings")
        print()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="SIFT-PROOF Audit & Replay Tool")
    p.add_argument('--finding_id', help='Replay a specific finding')
    p.add_argument('--all', action='store_true', help='Show all findings')
    p.add_argument('--audit', action='store_true', help='Show audit trail')
    args = p.parse_args()

    if args.finding_id:
        replay(args.finding_id)
    elif getattr(args, 'all'):
        show_all()
    elif args.audit:
        show_audit()
    else:
        print("Usage:")
        print("  python3 replay.py --finding_id a3f2b1c4")
        print("  python3 replay.py --all")
        print("  python3 replay.py --audit")