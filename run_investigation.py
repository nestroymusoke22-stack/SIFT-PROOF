
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(
        description="SIFT-PROOF — Autonomous Forensic Investigation Agent"
    )
    parser.add_argument('--image', help='Path to disk image file')
    parser.add_argument('--type', default='generic',
                        choices=['windows_compromise', 'ransomware', 'generic'],
                        help='Investigation type')
    parser.add_argument('--demo', action='store_true',
                        help='Run with pre-loaded test data (no image needed)')
    parser.add_argument('--backend', choices=['groq', 'ollama', 'anthropic'],
                        help='Override AI backend')
    parser.add_argument('--max-iter', type=int, default=25,
                        help='Maximum agent iterations (default: 25)')
    parser.add_argument('--report', help='Save final report to JSON file')

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

    # Demo mode: load test data and investigate it
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

        from agent.agent_loop import run_investigation
        report = run_investigation(args.image, args.type, args.max_iter)

    else:
        parser.print_help()
        print("\nExamples:")
        print("  python3 run_investigation.py --demo")
        print("  python3 run_investigation.py --image /cases/disk.dd --type windows_compromise")
        print("  python3 run_investigation.py --demo --backend ollama")
        sys.exit(0)

    # Save report if requested
    if args.report and report:
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nReport saved to: {args.report}")

    return report


if __name__ == "__main__":
    main()