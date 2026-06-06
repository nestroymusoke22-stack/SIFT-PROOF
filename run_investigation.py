import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

MEM_EXTENSIONS = ('.raw', '.mem', '.dmp', '.vmem', '.lime')


def main():
    parser = argparse.ArgumentParser(
        description="SIFT-PROOF — Autonomous Forensic Investigation Agent"
    )
    parser.add_argument('--image', help='Path to disk image or memory dump file')
    parser.add_argument('--type', default='generic',
                        choices=['windows_compromise', 'ransomware',
                                 'generic', 'memory_analysis'],
                        help='Investigation type (auto-detected for memory dumps)')
    parser.add_argument('--demo', action='store_true',
                        help='Run with pre-loaded test data (no image needed)')
    parser.add_argument('--backend', choices=['groq', 'ollama', 'anthropic'],
                        help='Override AI backend')
    parser.add_argument('--max-iter', type=int, default=25,
                        help='Maximum agent iterations (default: 25)')
    parser.add_argument('--report', help='Save final report to JSON file')
    parser.add_argument('--fresh', action='store_true',
                        help='Ignore saved checkpoint and start fresh')

    args = parser.parse_args()

    # Override backend if specified
    if args.backend:
        os.environ['AI_BACKEND'] = args.backend

    # Print backend info
    from agent.llm_client import get_backend_info
    info = get_backend_info()
    print(f"AI Backend: {info['backend']} — {info['model']} — {info['cost']}")

    if not info['key_set'] and info['backend'] != "Ollama (local)":
        print(f"WARNING: API key not set for {info['backend']}")
        print("For Groq: export GROQ_API_KEY='gsk_...'")
        sys.exit(1)

    # Clear checkpoint if --fresh requested
    if args.fresh:
        try:
            from agent.progress_state import clear_progress
            clear_progress()
        except Exception:
            pass

    # Demo mode
    if args.demo:
        print("\n[DEMO MODE] Loading test dataset...")
        from data.create_test_data import create_test_dataset
        create_test_dataset()
        print("[DEMO MODE] Test data loaded. Starting investigation in TEST_MODE...")

        from agent.agent_loop import run_investigation
        report = run_investigation("TEST_MODE", "windows_compromise", args.max_iter)

    elif args.image:
        if not os.path.exists(args.image):
            print(f"ERROR: Image file not found: {args.image}")
            sys.exit(1)

        # Auto-detect memory image — override type if needed
        image_lower = args.image.lower()
        is_memory = any(image_lower.endswith(ext) for ext in MEM_EXTENSIONS)
        if is_memory and args.type not in ('memory_analysis',):
            ext = os.path.splitext(args.image)[1]
            print(f"[AUTO] Memory image detected ({ext}) "
                  f"— switching to memory_analysis mode")
            args.type = "memory_analysis"

        # ── Dynamic evidence ingestion (Case A/B/C + cleanup) ──────────────
        # Memory dumps go straight to Volatility; disk images/E01 are mounted;
        # directories pass straight through.
        from core.mounting import prepare_evidence, teardown, MountError
        mounted = False
        target = args.image
        if not is_memory:
            try:
                target, mounted = prepare_evidence(args.image)
            except MountError as e:
                print(f"ERROR: {e}")
                sys.exit(2)

        from agent.agent_loop import run_investigation
        try:
            report = run_investigation(target, args.type, args.max_iter)
        finally:
            if mounted:
                print("[MOUNT] Tearing down mounts...")
                teardown()

    else:
        parser.print_help()
        print("\nExamples:")
        print("  python3 run_investigation.py --demo")
        print("  python3 run_investigation.py --image /cases/disk.dd --type windows_compromise")
        print("  python3 run_investigation.py --image /cases/memory.raw")
        print("  python3 run_investigation.py --demo --backend ollama")
        print("  python3 run_investigation.py --image /cases/disk.dd --fresh")
        sys.exit(0)

    # Save report if requested
    if args.report and report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nReport saved to: {args.report}")

    return report


if __name__ == "__main__":
    main()