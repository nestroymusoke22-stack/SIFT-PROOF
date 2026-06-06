import unittest
import sys
import os
import io
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))


def run():
    print("=" * 60)
    print("SIFT-PROOF TEST SUITE")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite  = loader.discover('tests', pattern='test_*.py')

    buf    = io.StringIO()
    runner = unittest.TextTestRunner(stream=buf, verbosity=2)

    start   = time.time()
    result  = runner.run(suite)
    elapsed = time.time() - start

    output = buf.getvalue()

    total  = result.testsRun
    failed = len(result.failures) + len(result.errors)
    passed = total - failed
    status_icon = "✅ ALL PASSING" if failed == 0 else f"❌ {failed} FAILING"

    # Print to terminal
    print(output)
    print(f"\n{'='*60}")
    print(f"  {status_icon}")
    print(f"  {passed}/{total} tests passed in {elapsed:.2f}s")
    print(f"{'='*60}")

    # Write markdown report
    os.makedirs('docs', exist_ok=True)
    with open('docs/test_results.md', 'w') as f:
        f.write("# SIFT-PROOF — Automated Test Results\n\n")
        f.write(f"> Last run: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write(f"## Status: {status_icon}\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Total Tests | **{total}** |\n")
        f.write(f"| Passed      | **{passed}** |\n")
        f.write(f"| Failed      | **{failed}** |\n")
        f.write(f"| Runtime     | {elapsed:.2f}s |\n\n")

        f.write("## What Each Test Proves\n\n")
        f.write("| Test Class | What It Demonstrates |\n")
        f.write("|-----------|----------------------|\n")
        f.write("| `TestSanitizer` | Command injection is architecturally blocked |\n")
        f.write("| `TestAssertionEngine` | Hallucinations cannot enter the report |\n")
        f.write("| `TestCoverageGate` | Incomplete investigations cannot conclude |\n")
        f.write("| `TestEvidenceIntegrity` | SHA256 chain of custody verified |\n")
        f.write("| `TestMassiveForensicMatrix` | Scale, EVTX schemas, temporal consistency, and STIX validation |\n\n")

        if result.failures:
            f.write("## Failures\n\n")
            for test, tb in result.failures:
                f.write(f"### {test}\n```\n{tb}\n```\n\n")

        if result.errors:
            f.write("## Errors\n\n")
            for test, tb in result.errors:
                f.write(f"### {test}\n```\n{tb}\n```\n\n")

        f.write("## Full Output\n\n```\n")
        f.write(output)
        f.write("\n```\n")

    print(f"\n📊 Report written to: docs/test_results.md")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run())