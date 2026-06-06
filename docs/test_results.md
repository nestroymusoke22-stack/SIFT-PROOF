# SIFT-PROOF — Automated Test Results

> Last run: 2026-06-04 20:08:40 UTC

## Status: ✅ ALL PASSING

| Metric | Value |
|--------|-------|
| Total Tests | **621** |
| Passed      | **621** |
| Failed      | **0** |
| Runtime     | 0.12s |

## What Each Test Proves

| Test Class | What It Demonstrates |
|-----------|----------------------|
| `TestSanitizer` | Command injection is architecturally blocked |
| `TestAssertionEngine` | Hallucinations cannot enter the report |
| `TestCoverageGate` | Incomplete investigations cannot conclude |
| `TestEvidenceIntegrity` | SHA256 chain of custody verified |
| `TestMassiveForensicMatrix` | Scale, EVTX schemas, temporal consistency, and STIX validation |

## Full Output

```
test_evidence_insert_blocked (test_forensics.TestAssertionEngine.test_evidence_insert_blocked) ... ok
test_evidence_write_blocked (test_forensics.TestAssertionEngine.test_evidence_write_blocked)
The database must be read-only from the assertion layer. ... ok
test_invented_claim_rejected (test_forensics.TestAssertionEngine.test_invented_claim_rejected) ... ok
test_temporal_contradiction_fires (test_forensics.TestAssertionEngine.test_temporal_contradiction_fires)
evil.exe deleted at 03:12 but prefetch shows it ran at 03:17. ... ok
test_valid_claim_confirmed (test_forensics.TestAssertionEngine.test_valid_claim_confirmed) ... ok
test_100_percent_when_all_covered (test_forensics.TestCoverageGate.test_100_percent_when_all_covered) ... ok
test_complete_investigation_passes (test_forensics.TestCoverageGate.test_complete_investigation_passes) ... ok
test_coverage_report_has_required_fields (test_forensics.TestCoverageGate.test_coverage_report_has_required_fields) ... ok
test_incomplete_investigation_blocked (test_forensics.TestCoverageGate.test_incomplete_investigation_blocked) ... ok
test_audit_log_clear_event_exists (test_forensics.TestEvidenceIntegrity.test_audit_log_clear_event_exists) ... ok
test_evil_exe_deleted_before_run (test_forensics.TestEvidenceIntegrity.test_evil_exe_deleted_before_run)
The impossible sequence must be in the database. ... ok
test_registry_persistence_exists (test_forensics.TestEvidenceIntegrity.test_registry_persistence_exists) ... ok
test_sha256_chain_present (test_forensics.TestEvidenceIntegrity.test_sha256_chain_present) ... ok
test_allows_safe_fls_args (test_forensics.TestSanitizer.test_allows_safe_fls_args) ... ok
test_allows_safe_vol_args (test_forensics.TestSanitizer.test_allows_safe_vol_args) ... ok
test_blocks_destructive_rm (test_forensics.TestSanitizer.test_blocks_destructive_rm) ... ok
test_blocks_double_ampersand (test_forensics.TestSanitizer.test_blocks_double_ampersand) ... ok
test_blocks_pipe_injection (test_forensics.TestSanitizer.test_blocks_pipe_injection) ... ok
test_blocks_semicolon_injection (test_forensics.TestSanitizer.test_blocks_semicolon_injection) ... ok
test_cmd	$(DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	$(DELETE) ... ok
test_cmd	$(DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	$(DROP) ... ok
test_cmd	$(del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	$(del) ... ok
test_cmd	$(format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	$(format) ... ok
test_cmd	$(rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	$(rm) ... ok
test_cmd	&&DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	&&DELETE) ... ok
test_cmd	&&DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	&&DROP) ... ok
test_cmd	&&del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	&&del) ... ok
test_cmd	&&format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	&&format) ... ok
test_cmd	&&rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	&&rm) ... ok
test_cmd	)DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	)DELETE) ... ok
test_cmd	)DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	)DROP) ... ok
test_cmd	)del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	)del) ... ok
test_cmd	)format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	)format) ... ok
test_cmd	)rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	)rm) ... ok
test_cmd	;DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	;DELETE) ... ok
test_cmd	;DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	;DROP) ... ok
test_cmd	;del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	;del) ... ok
test_cmd	;format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	;format) ... ok
test_cmd	;rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	;rm) ... ok
test_cmd	`DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	`DELETE) ... ok
test_cmd	`DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	`DROP) ... ok
test_cmd	`del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	`del) ... ok
test_cmd	`format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	`format) ... ok
test_cmd	`rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	`rm) ... ok
test_cmd	|DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	|DELETE) ... ok
test_cmd	|DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	|DROP) ... ok
test_cmd	|del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	|del) ... ok
test_cmd	|format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	|format) ... ok
test_cmd	|rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	|rm) ... ok
test_cmd	||DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	||DELETE) ... ok
test_cmd	||DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	||DROP) ... ok
test_cmd	||del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	||del) ... ok
test_cmd	||format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	||format) ... ok
test_cmd	||rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd	||rm) ... ok
test_cmd   $(DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   $(DELETE) ... ok
test_cmd   $(DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   $(DROP) ... ok
test_cmd   $(del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   $(del) ... ok
test_cmd   $(format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   $(format) ... ok
test_cmd   $(rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   $(rm) ... ok
test_cmd   &&DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   &&DELETE) ... ok
test_cmd   &&DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   &&DROP) ... ok
test_cmd   &&del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   &&del) ... ok
test_cmd   &&format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   &&format) ... ok
test_cmd   &&rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   &&rm) ... ok
test_cmd   )DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   )DELETE) ... ok
test_cmd   )DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   )DROP) ... ok
test_cmd   )del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   )del) ... ok
test_cmd   )format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   )format) ... ok
test_cmd   )rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   )rm) ... ok
test_cmd   ;DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ;DELETE) ... ok
test_cmd   ;DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ;DROP) ... ok
test_cmd   ;del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ;del) ... ok
test_cmd   ;format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ;format) ... ok
test_cmd   ;rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ;rm) ... ok
test_cmd   `DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   `DELETE) ... ok
test_cmd   `DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   `DROP) ... ok
test_cmd   `del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   `del) ... ok
test_cmd   `format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   `format) ... ok
test_cmd   `rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   `rm) ... ok
test_cmd   |DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   |DELETE) ... ok
test_cmd   |DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   |DROP) ... ok
test_cmd   |del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   |del) ... ok
test_cmd   |format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   |format) ... ok
test_cmd   |rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   |rm) ... ok
test_cmd   ||DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ||DELETE) ... ok
test_cmd   ||DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ||DROP) ... ok
test_cmd   ||del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ||del) ... ok
test_cmd   ||format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ||format) ... ok
test_cmd   ||rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd   ||rm) ... ok
test_cmd $(DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd $(DELETE) ... ok
test_cmd $(DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd $(DROP) ... ok
test_cmd $(del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd $(del) ... ok
test_cmd $(format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd $(format) ... ok
test_cmd $(rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd $(rm) ... ok
test_cmd &&DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd &&DELETE) ... ok
test_cmd &&DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd &&DROP) ... ok
test_cmd &&del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd &&del) ... ok
test_cmd &&format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd &&format) ... ok
test_cmd &&rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd &&rm) ... ok
test_cmd )DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd )DELETE) ... ok
test_cmd )DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd )DROP) ... ok
test_cmd )del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd )del) ... ok
test_cmd )format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd )format) ... ok
test_cmd )rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd )rm) ... ok
test_cmd ;DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ;DELETE) ... ok
test_cmd ;DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ;DROP) ... ok
test_cmd ;del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ;del) ... ok
test_cmd ;format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ;format) ... ok
test_cmd ;rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ;rm) ... ok
test_cmd `DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd `DELETE) ... ok
test_cmd `DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd `DROP) ... ok
test_cmd `del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd `del) ... ok
test_cmd `format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd `format) ... ok
test_cmd `rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd `rm) ... ok
test_cmd |DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd |DELETE) ... ok
test_cmd |DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd |DROP) ... ok
test_cmd |del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd |del) ... ok
test_cmd |format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd |format) ... ok
test_cmd |rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd |rm) ... ok
test_cmd ||DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ||DELETE) ... ok
test_cmd ||DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ||DROP) ... ok
test_cmd ||del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ||del) ... ok
test_cmd ||format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ||format) ... ok
test_cmd ||rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd ||rm) ... ok
test_cmd$(DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd$(DELETE) ... ok
test_cmd$(DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd$(DROP) ... ok
test_cmd$(del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd$(del) ... ok
test_cmd$(format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd$(format) ... ok
test_cmd$(rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd$(rm) ... ok
test_cmd&&DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd&&DELETE) ... ok
test_cmd&&DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd&&DROP) ... ok
test_cmd&&del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd&&del) ... ok
test_cmd&&format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd&&format) ... ok
test_cmd&&rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd&&rm) ... ok
test_cmd)DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd)DELETE) ... ok
test_cmd)DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd)DROP) ... ok
test_cmd)del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd)del) ... ok
test_cmd)format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd)format) ... ok
test_cmd)rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd)rm) ... ok
test_cmd;DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd;DELETE) ... ok
test_cmd;DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd;DROP) ... ok
test_cmd;del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd;del) ... ok
test_cmd;format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd;format) ... ok
test_cmd;rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd;rm) ... ok
test_cmd`DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd`DELETE) ... ok
test_cmd`DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd`DROP) ... ok
test_cmd`del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd`del) ... ok
test_cmd`format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd`format) ... ok
test_cmd`rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd`rm) ... ok
test_cmd|DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd|DELETE) ... ok
test_cmd|DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd|DROP) ... ok
test_cmd|del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd|del) ... ok
test_cmd|format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd|format) ... ok
test_cmd|rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd|rm) ... ok
test_cmd||DELETE (test_massive_matrix.TestMassiveForensicMatrix.test_cmd||DELETE) ... ok
test_cmd||DROP (test_massive_matrix.TestMassiveForensicMatrix.test_cmd||DROP) ... ok
test_cmd||del (test_massive_matrix.TestMassiveForensicMatrix.test_cmd||del) ... ok
test_cmd||format (test_massive_matrix.TestMassiveForensicMatrix.test_cmd||format) ... ok
test_cmd||rm (test_massive_matrix.TestMassiveForensicMatrix.test_cmd||rm) ... ok
test_evtx_id_1036_corrupted_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_corrupted_idx_0) ... ok
test_evtx_id_1036_corrupted_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_corrupted_idx_1) ... ok
test_evtx_id_1036_corrupted_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_corrupted_idx_2) ... ok
test_evtx_id_1036_corrupted_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_corrupted_idx_3) ... ok
test_evtx_id_1036_corrupted_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_corrupted_idx_4) ... ok
test_evtx_id_1036_failure_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_failure_idx_0) ... ok
test_evtx_id_1036_failure_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_failure_idx_1) ... ok
test_evtx_id_1036_failure_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_failure_idx_2) ... ok
test_evtx_id_1036_failure_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_failure_idx_3) ... ok
test_evtx_id_1036_failure_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_failure_idx_4) ... ok
test_evtx_id_1036_overflow_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_overflow_idx_0) ... ok
test_evtx_id_1036_overflow_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_overflow_idx_1) ... ok
test_evtx_id_1036_overflow_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_overflow_idx_2) ... ok
test_evtx_id_1036_overflow_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_overflow_idx_3) ... ok
test_evtx_id_1036_overflow_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_overflow_idx_4) ... ok
test_evtx_id_1036_success_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_success_idx_0) ... ok
test_evtx_id_1036_success_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_success_idx_1) ... ok
test_evtx_id_1036_success_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_success_idx_2) ... ok
test_evtx_id_1036_success_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_success_idx_3) ... ok
test_evtx_id_1036_success_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_success_idx_4) ... ok
test_evtx_id_1036_tampered_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_tampered_idx_0) ... ok
test_evtx_id_1036_tampered_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_tampered_idx_1) ... ok
test_evtx_id_1036_tampered_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_tampered_idx_2) ... ok
test_evtx_id_1036_tampered_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_tampered_idx_3) ... ok
test_evtx_id_1036_tampered_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1036_tampered_idx_4) ... ok
test_evtx_id_1102_corrupted_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_corrupted_idx_0) ... ok
test_evtx_id_1102_corrupted_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_corrupted_idx_1) ... ok
test_evtx_id_1102_corrupted_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_corrupted_idx_2) ... ok
test_evtx_id_1102_corrupted_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_corrupted_idx_3) ... ok
test_evtx_id_1102_corrupted_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_corrupted_idx_4) ... ok
test_evtx_id_1102_failure_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_failure_idx_0) ... ok
test_evtx_id_1102_failure_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_failure_idx_1) ... ok
test_evtx_id_1102_failure_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_failure_idx_2) ... ok
test_evtx_id_1102_failure_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_failure_idx_3) ... ok
test_evtx_id_1102_failure_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_failure_idx_4) ... ok
test_evtx_id_1102_overflow_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_overflow_idx_0) ... ok
test_evtx_id_1102_overflow_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_overflow_idx_1) ... ok
test_evtx_id_1102_overflow_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_overflow_idx_2) ... ok
test_evtx_id_1102_overflow_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_overflow_idx_3) ... ok
test_evtx_id_1102_overflow_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_overflow_idx_4) ... ok
test_evtx_id_1102_success_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_success_idx_0) ... ok
test_evtx_id_1102_success_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_success_idx_1) ... ok
test_evtx_id_1102_success_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_success_idx_2) ... ok
test_evtx_id_1102_success_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_success_idx_3) ... ok
test_evtx_id_1102_success_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_success_idx_4) ... ok
test_evtx_id_1102_tampered_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_tampered_idx_0) ... ok
test_evtx_id_1102_tampered_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_tampered_idx_1) ... ok
test_evtx_id_1102_tampered_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_tampered_idx_2) ... ok
test_evtx_id_1102_tampered_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_tampered_idx_3) ... ok
test_evtx_id_1102_tampered_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_1102_tampered_idx_4) ... ok
test_evtx_id_4624_corrupted_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_corrupted_idx_0) ... ok
test_evtx_id_4624_corrupted_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_corrupted_idx_1) ... ok
test_evtx_id_4624_corrupted_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_corrupted_idx_2) ... ok
test_evtx_id_4624_corrupted_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_corrupted_idx_3) ... ok
test_evtx_id_4624_corrupted_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_corrupted_idx_4) ... ok
test_evtx_id_4624_failure_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_failure_idx_0) ... ok
test_evtx_id_4624_failure_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_failure_idx_1) ... ok
test_evtx_id_4624_failure_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_failure_idx_2) ... ok
test_evtx_id_4624_failure_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_failure_idx_3) ... ok
test_evtx_id_4624_failure_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_failure_idx_4) ... ok
test_evtx_id_4624_overflow_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_overflow_idx_0) ... ok
test_evtx_id_4624_overflow_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_overflow_idx_1) ... ok
test_evtx_id_4624_overflow_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_overflow_idx_2) ... ok
test_evtx_id_4624_overflow_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_overflow_idx_3) ... ok
test_evtx_id_4624_overflow_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_overflow_idx_4) ... ok
test_evtx_id_4624_success_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_success_idx_0) ... ok
test_evtx_id_4624_success_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_success_idx_1) ... ok
test_evtx_id_4624_success_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_success_idx_2) ... ok
test_evtx_id_4624_success_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_success_idx_3) ... ok
test_evtx_id_4624_success_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_success_idx_4) ... ok
test_evtx_id_4624_tampered_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_tampered_idx_0) ... ok
test_evtx_id_4624_tampered_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_tampered_idx_1) ... ok
test_evtx_id_4624_tampered_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_tampered_idx_2) ... ok
test_evtx_id_4624_tampered_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_tampered_idx_3) ... ok
test_evtx_id_4624_tampered_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4624_tampered_idx_4) ... ok
test_evtx_id_4625_corrupted_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_corrupted_idx_0) ... ok
test_evtx_id_4625_corrupted_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_corrupted_idx_1) ... ok
test_evtx_id_4625_corrupted_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_corrupted_idx_2) ... ok
test_evtx_id_4625_corrupted_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_corrupted_idx_3) ... ok
test_evtx_id_4625_corrupted_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_corrupted_idx_4) ... ok
test_evtx_id_4625_failure_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_failure_idx_0) ... ok
test_evtx_id_4625_failure_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_failure_idx_1) ... ok
test_evtx_id_4625_failure_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_failure_idx_2) ... ok
test_evtx_id_4625_failure_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_failure_idx_3) ... ok
test_evtx_id_4625_failure_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_failure_idx_4) ... ok
test_evtx_id_4625_overflow_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_overflow_idx_0) ... ok
test_evtx_id_4625_overflow_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_overflow_idx_1) ... ok
test_evtx_id_4625_overflow_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_overflow_idx_2) ... ok
test_evtx_id_4625_overflow_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_overflow_idx_3) ... ok
test_evtx_id_4625_overflow_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_overflow_idx_4) ... ok
test_evtx_id_4625_success_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_success_idx_0) ... ok
test_evtx_id_4625_success_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_success_idx_1) ... ok
test_evtx_id_4625_success_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_success_idx_2) ... ok
test_evtx_id_4625_success_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_success_idx_3) ... ok
test_evtx_id_4625_success_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_success_idx_4) ... ok
test_evtx_id_4625_tampered_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_tampered_idx_0) ... ok
test_evtx_id_4625_tampered_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_tampered_idx_1) ... ok
test_evtx_id_4625_tampered_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_tampered_idx_2) ... ok
test_evtx_id_4625_tampered_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_tampered_idx_3) ... ok
test_evtx_id_4625_tampered_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4625_tampered_idx_4) ... ok
test_evtx_id_4672_corrupted_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_corrupted_idx_0) ... ok
test_evtx_id_4672_corrupted_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_corrupted_idx_1) ... ok
test_evtx_id_4672_corrupted_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_corrupted_idx_2) ... ok
test_evtx_id_4672_corrupted_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_corrupted_idx_3) ... ok
test_evtx_id_4672_corrupted_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_corrupted_idx_4) ... ok
test_evtx_id_4672_failure_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_failure_idx_0) ... ok
test_evtx_id_4672_failure_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_failure_idx_1) ... ok
test_evtx_id_4672_failure_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_failure_idx_2) ... ok
test_evtx_id_4672_failure_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_failure_idx_3) ... ok
test_evtx_id_4672_failure_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_failure_idx_4) ... ok
test_evtx_id_4672_overflow_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_overflow_idx_0) ... ok
test_evtx_id_4672_overflow_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_overflow_idx_1) ... ok
test_evtx_id_4672_overflow_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_overflow_idx_2) ... ok
test_evtx_id_4672_overflow_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_overflow_idx_3) ... ok
test_evtx_id_4672_overflow_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_overflow_idx_4) ... ok
test_evtx_id_4672_success_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_success_idx_0) ... ok
test_evtx_id_4672_success_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_success_idx_1) ... ok
test_evtx_id_4672_success_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_success_idx_2) ... ok
test_evtx_id_4672_success_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_success_idx_3) ... ok
test_evtx_id_4672_success_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_success_idx_4) ... ok
test_evtx_id_4672_tampered_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_tampered_idx_0) ... ok
test_evtx_id_4672_tampered_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_tampered_idx_1) ... ok
test_evtx_id_4672_tampered_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_tampered_idx_2) ... ok
test_evtx_id_4672_tampered_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_tampered_idx_3) ... ok
test_evtx_id_4672_tampered_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_4672_tampered_idx_4) ... ok
test_evtx_id_7045_corrupted_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_corrupted_idx_0) ... ok
test_evtx_id_7045_corrupted_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_corrupted_idx_1) ... ok
test_evtx_id_7045_corrupted_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_corrupted_idx_2) ... ok
test_evtx_id_7045_corrupted_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_corrupted_idx_3) ... ok
test_evtx_id_7045_corrupted_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_corrupted_idx_4) ... ok
test_evtx_id_7045_failure_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_failure_idx_0) ... ok
test_evtx_id_7045_failure_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_failure_idx_1) ... ok
test_evtx_id_7045_failure_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_failure_idx_2) ... ok
test_evtx_id_7045_failure_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_failure_idx_3) ... ok
test_evtx_id_7045_failure_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_failure_idx_4) ... ok
test_evtx_id_7045_overflow_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_overflow_idx_0) ... ok
test_evtx_id_7045_overflow_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_overflow_idx_1) ... ok
test_evtx_id_7045_overflow_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_overflow_idx_2) ... ok
test_evtx_id_7045_overflow_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_overflow_idx_3) ... ok
test_evtx_id_7045_overflow_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_overflow_idx_4) ... ok
test_evtx_id_7045_success_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_success_idx_0) ... ok
test_evtx_id_7045_success_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_success_idx_1) ... ok
test_evtx_id_7045_success_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_success_idx_2) ... ok
test_evtx_id_7045_success_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_success_idx_3) ... ok
test_evtx_id_7045_success_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_success_idx_4) ... ok
test_evtx_id_7045_tampered_idx_0 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_tampered_idx_0) ... ok
test_evtx_id_7045_tampered_idx_1 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_tampered_idx_1) ... ok
test_evtx_id_7045_tampered_idx_2 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_tampered_idx_2) ... ok
test_evtx_id_7045_tampered_idx_3 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_tampered_idx_3) ... ok
test_evtx_id_7045_tampered_idx_4 (test_massive_matrix.TestMassiveForensicMatrix.test_evtx_id_7045_tampered_idx_4) ... ok
test_stix_proof_file_path_critical_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_0) ... ok
test_stix_proof_file_path_critical_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_1) ... ok
test_stix_proof_file_path_critical_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_10) ... ok
test_stix_proof_file_path_critical_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_11) ... ok
test_stix_proof_file_path_critical_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_2) ... ok
test_stix_proof_file_path_critical_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_3) ... ok
test_stix_proof_file_path_critical_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_4) ... ok
test_stix_proof_file_path_critical_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_5) ... ok
test_stix_proof_file_path_critical_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_6) ... ok
test_stix_proof_file_path_critical_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_7) ... ok
test_stix_proof_file_path_critical_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_8) ... ok
test_stix_proof_file_path_critical_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_critical_r_9) ... ok
test_stix_proof_file_path_high_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_0) ... ok
test_stix_proof_file_path_high_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_1) ... ok
test_stix_proof_file_path_high_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_10) ... ok
test_stix_proof_file_path_high_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_11) ... ok
test_stix_proof_file_path_high_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_2) ... ok
test_stix_proof_file_path_high_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_3) ... ok
test_stix_proof_file_path_high_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_4) ... ok
test_stix_proof_file_path_high_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_5) ... ok
test_stix_proof_file_path_high_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_6) ... ok
test_stix_proof_file_path_high_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_7) ... ok
test_stix_proof_file_path_high_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_8) ... ok
test_stix_proof_file_path_high_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_high_r_9) ... ok
test_stix_proof_file_path_low_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_0) ... ok
test_stix_proof_file_path_low_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_1) ... ok
test_stix_proof_file_path_low_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_10) ... ok
test_stix_proof_file_path_low_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_11) ... ok
test_stix_proof_file_path_low_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_2) ... ok
test_stix_proof_file_path_low_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_3) ... ok
test_stix_proof_file_path_low_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_4) ... ok
test_stix_proof_file_path_low_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_5) ... ok
test_stix_proof_file_path_low_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_6) ... ok
test_stix_proof_file_path_low_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_7) ... ok
test_stix_proof_file_path_low_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_8) ... ok
test_stix_proof_file_path_low_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_low_r_9) ... ok
test_stix_proof_file_path_medium_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_0) ... ok
test_stix_proof_file_path_medium_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_1) ... ok
test_stix_proof_file_path_medium_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_10) ... ok
test_stix_proof_file_path_medium_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_11) ... ok
test_stix_proof_file_path_medium_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_2) ... ok
test_stix_proof_file_path_medium_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_3) ... ok
test_stix_proof_file_path_medium_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_4) ... ok
test_stix_proof_file_path_medium_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_5) ... ok
test_stix_proof_file_path_medium_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_6) ... ok
test_stix_proof_file_path_medium_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_7) ... ok
test_stix_proof_file_path_medium_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_8) ... ok
test_stix_proof_file_path_medium_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_file_path_medium_r_9) ... ok
test_stix_proof_ipv4_critical_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_0) ... ok
test_stix_proof_ipv4_critical_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_1) ... ok
test_stix_proof_ipv4_critical_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_10) ... ok
test_stix_proof_ipv4_critical_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_11) ... ok
test_stix_proof_ipv4_critical_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_2) ... ok
test_stix_proof_ipv4_critical_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_3) ... ok
test_stix_proof_ipv4_critical_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_4) ... ok
test_stix_proof_ipv4_critical_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_5) ... ok
test_stix_proof_ipv4_critical_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_6) ... ok
test_stix_proof_ipv4_critical_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_7) ... ok
test_stix_proof_ipv4_critical_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_8) ... ok
test_stix_proof_ipv4_critical_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_critical_r_9) ... ok
test_stix_proof_ipv4_high_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_0) ... ok
test_stix_proof_ipv4_high_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_1) ... ok
test_stix_proof_ipv4_high_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_10) ... ok
test_stix_proof_ipv4_high_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_11) ... ok
test_stix_proof_ipv4_high_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_2) ... ok
test_stix_proof_ipv4_high_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_3) ... ok
test_stix_proof_ipv4_high_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_4) ... ok
test_stix_proof_ipv4_high_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_5) ... ok
test_stix_proof_ipv4_high_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_6) ... ok
test_stix_proof_ipv4_high_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_7) ... ok
test_stix_proof_ipv4_high_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_8) ... ok
test_stix_proof_ipv4_high_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_high_r_9) ... ok
test_stix_proof_ipv4_low_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_0) ... ok
test_stix_proof_ipv4_low_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_1) ... ok
test_stix_proof_ipv4_low_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_10) ... ok
test_stix_proof_ipv4_low_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_11) ... ok
test_stix_proof_ipv4_low_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_2) ... ok
test_stix_proof_ipv4_low_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_3) ... ok
test_stix_proof_ipv4_low_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_4) ... ok
test_stix_proof_ipv4_low_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_5) ... ok
test_stix_proof_ipv4_low_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_6) ... ok
test_stix_proof_ipv4_low_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_7) ... ok
test_stix_proof_ipv4_low_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_8) ... ok
test_stix_proof_ipv4_low_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_low_r_9) ... ok
test_stix_proof_ipv4_medium_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_0) ... ok
test_stix_proof_ipv4_medium_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_1) ... ok
test_stix_proof_ipv4_medium_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_10) ... ok
test_stix_proof_ipv4_medium_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_11) ... ok
test_stix_proof_ipv4_medium_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_2) ... ok
test_stix_proof_ipv4_medium_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_3) ... ok
test_stix_proof_ipv4_medium_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_4) ... ok
test_stix_proof_ipv4_medium_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_5) ... ok
test_stix_proof_ipv4_medium_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_6) ... ok
test_stix_proof_ipv4_medium_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_7) ... ok
test_stix_proof_ipv4_medium_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_8) ... ok
test_stix_proof_ipv4_medium_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_ipv4_medium_r_9) ... ok
test_stix_proof_md5_critical_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_0) ... ok
test_stix_proof_md5_critical_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_1) ... ok
test_stix_proof_md5_critical_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_10) ... ok
test_stix_proof_md5_critical_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_11) ... ok
test_stix_proof_md5_critical_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_2) ... ok
test_stix_proof_md5_critical_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_3) ... ok
test_stix_proof_md5_critical_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_4) ... ok
test_stix_proof_md5_critical_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_5) ... ok
test_stix_proof_md5_critical_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_6) ... ok
test_stix_proof_md5_critical_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_7) ... ok
test_stix_proof_md5_critical_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_8) ... ok
test_stix_proof_md5_critical_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_critical_r_9) ... ok
test_stix_proof_md5_high_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_0) ... ok
test_stix_proof_md5_high_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_1) ... ok
test_stix_proof_md5_high_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_10) ... ok
test_stix_proof_md5_high_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_11) ... ok
test_stix_proof_md5_high_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_2) ... ok
test_stix_proof_md5_high_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_3) ... ok
test_stix_proof_md5_high_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_4) ... ok
test_stix_proof_md5_high_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_5) ... ok
test_stix_proof_md5_high_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_6) ... ok
test_stix_proof_md5_high_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_7) ... ok
test_stix_proof_md5_high_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_8) ... ok
test_stix_proof_md5_high_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_high_r_9) ... ok
test_stix_proof_md5_low_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_0) ... ok
test_stix_proof_md5_low_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_1) ... ok
test_stix_proof_md5_low_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_10) ... ok
test_stix_proof_md5_low_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_11) ... ok
test_stix_proof_md5_low_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_2) ... ok
test_stix_proof_md5_low_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_3) ... ok
test_stix_proof_md5_low_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_4) ... ok
test_stix_proof_md5_low_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_5) ... ok
test_stix_proof_md5_low_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_6) ... ok
test_stix_proof_md5_low_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_7) ... ok
test_stix_proof_md5_low_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_8) ... ok
test_stix_proof_md5_low_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_low_r_9) ... ok
test_stix_proof_md5_medium_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_0) ... ok
test_stix_proof_md5_medium_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_1) ... ok
test_stix_proof_md5_medium_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_10) ... ok
test_stix_proof_md5_medium_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_11) ... ok
test_stix_proof_md5_medium_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_2) ... ok
test_stix_proof_md5_medium_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_3) ... ok
test_stix_proof_md5_medium_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_4) ... ok
test_stix_proof_md5_medium_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_5) ... ok
test_stix_proof_md5_medium_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_6) ... ok
test_stix_proof_md5_medium_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_7) ... ok
test_stix_proof_md5_medium_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_8) ... ok
test_stix_proof_md5_medium_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_md5_medium_r_9) ... ok
test_stix_proof_registry_key_critical_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_0) ... ok
test_stix_proof_registry_key_critical_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_1) ... ok
test_stix_proof_registry_key_critical_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_10) ... ok
test_stix_proof_registry_key_critical_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_11) ... ok
test_stix_proof_registry_key_critical_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_2) ... ok
test_stix_proof_registry_key_critical_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_3) ... ok
test_stix_proof_registry_key_critical_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_4) ... ok
test_stix_proof_registry_key_critical_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_5) ... ok
test_stix_proof_registry_key_critical_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_6) ... ok
test_stix_proof_registry_key_critical_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_7) ... ok
test_stix_proof_registry_key_critical_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_8) ... ok
test_stix_proof_registry_key_critical_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_critical_r_9) ... ok
test_stix_proof_registry_key_high_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_0) ... ok
test_stix_proof_registry_key_high_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_1) ... ok
test_stix_proof_registry_key_high_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_10) ... ok
test_stix_proof_registry_key_high_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_11) ... ok
test_stix_proof_registry_key_high_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_2) ... ok
test_stix_proof_registry_key_high_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_3) ... ok
test_stix_proof_registry_key_high_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_4) ... ok
test_stix_proof_registry_key_high_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_5) ... ok
test_stix_proof_registry_key_high_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_6) ... ok
test_stix_proof_registry_key_high_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_7) ... ok
test_stix_proof_registry_key_high_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_8) ... ok
test_stix_proof_registry_key_high_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_high_r_9) ... ok
test_stix_proof_registry_key_low_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_0) ... ok
test_stix_proof_registry_key_low_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_1) ... ok
test_stix_proof_registry_key_low_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_10) ... ok
test_stix_proof_registry_key_low_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_11) ... ok
test_stix_proof_registry_key_low_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_2) ... ok
test_stix_proof_registry_key_low_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_3) ... ok
test_stix_proof_registry_key_low_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_4) ... ok
test_stix_proof_registry_key_low_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_5) ... ok
test_stix_proof_registry_key_low_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_6) ... ok
test_stix_proof_registry_key_low_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_7) ... ok
test_stix_proof_registry_key_low_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_8) ... ok
test_stix_proof_registry_key_low_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_low_r_9) ... ok
test_stix_proof_registry_key_medium_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_0) ... ok
test_stix_proof_registry_key_medium_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_1) ... ok
test_stix_proof_registry_key_medium_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_10) ... ok
test_stix_proof_registry_key_medium_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_11) ... ok
test_stix_proof_registry_key_medium_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_2) ... ok
test_stix_proof_registry_key_medium_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_3) ... ok
test_stix_proof_registry_key_medium_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_4) ... ok
test_stix_proof_registry_key_medium_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_5) ... ok
test_stix_proof_registry_key_medium_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_6) ... ok
test_stix_proof_registry_key_medium_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_7) ... ok
test_stix_proof_registry_key_medium_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_8) ... ok
test_stix_proof_registry_key_medium_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_registry_key_medium_r_9) ... ok
test_stix_proof_sha256_critical_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_0) ... ok
test_stix_proof_sha256_critical_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_1) ... ok
test_stix_proof_sha256_critical_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_10) ... ok
test_stix_proof_sha256_critical_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_11) ... ok
test_stix_proof_sha256_critical_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_2) ... ok
test_stix_proof_sha256_critical_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_3) ... ok
test_stix_proof_sha256_critical_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_4) ... ok
test_stix_proof_sha256_critical_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_5) ... ok
test_stix_proof_sha256_critical_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_6) ... ok
test_stix_proof_sha256_critical_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_7) ... ok
test_stix_proof_sha256_critical_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_8) ... ok
test_stix_proof_sha256_critical_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_critical_r_9) ... ok
test_stix_proof_sha256_high_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_0) ... ok
test_stix_proof_sha256_high_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_1) ... ok
test_stix_proof_sha256_high_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_10) ... ok
test_stix_proof_sha256_high_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_11) ... ok
test_stix_proof_sha256_high_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_2) ... ok
test_stix_proof_sha256_high_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_3) ... ok
test_stix_proof_sha256_high_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_4) ... ok
test_stix_proof_sha256_high_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_5) ... ok
test_stix_proof_sha256_high_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_6) ... ok
test_stix_proof_sha256_high_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_7) ... ok
test_stix_proof_sha256_high_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_8) ... ok
test_stix_proof_sha256_high_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_high_r_9) ... ok
test_stix_proof_sha256_low_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_0) ... ok
test_stix_proof_sha256_low_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_1) ... ok
test_stix_proof_sha256_low_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_10) ... ok
test_stix_proof_sha256_low_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_11) ... ok
test_stix_proof_sha256_low_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_2) ... ok
test_stix_proof_sha256_low_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_3) ... ok
test_stix_proof_sha256_low_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_4) ... ok
test_stix_proof_sha256_low_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_5) ... ok
test_stix_proof_sha256_low_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_6) ... ok
test_stix_proof_sha256_low_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_7) ... ok
test_stix_proof_sha256_low_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_8) ... ok
test_stix_proof_sha256_low_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_low_r_9) ... ok
test_stix_proof_sha256_medium_r_0 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_0) ... ok
test_stix_proof_sha256_medium_r_1 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_1) ... ok
test_stix_proof_sha256_medium_r_10 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_10) ... ok
test_stix_proof_sha256_medium_r_11 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_11) ... ok
test_stix_proof_sha256_medium_r_2 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_2) ... ok
test_stix_proof_sha256_medium_r_3 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_3) ... ok
test_stix_proof_sha256_medium_r_4 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_4) ... ok
test_stix_proof_sha256_medium_r_5 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_5) ... ok
test_stix_proof_sha256_medium_r_6 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_6) ... ok
test_stix_proof_sha256_medium_r_7 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_7) ... ok
test_stix_proof_sha256_medium_r_8 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_8) ... ok
test_stix_proof_sha256_medium_r_9 (test_massive_matrix.TestMassiveForensicMatrix.test_stix_proof_sha256_medium_r_9) ... ok
test_timeline_anomaly_2020_1 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_1) ... ok
test_timeline_anomaly_2020_10 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_10) ... ok
test_timeline_anomaly_2020_11 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_11) ... ok
test_timeline_anomaly_2020_12 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_12) ... ok
test_timeline_anomaly_2020_2 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_2) ... ok
test_timeline_anomaly_2020_3 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_3) ... ok
test_timeline_anomaly_2020_4 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_4) ... ok
test_timeline_anomaly_2020_5 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_5) ... ok
test_timeline_anomaly_2020_6 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_6) ... ok
test_timeline_anomaly_2020_7 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_7) ... ok
test_timeline_anomaly_2020_8 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_8) ... ok
test_timeline_anomaly_2020_9 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2020_9) ... ok
test_timeline_anomaly_2021_1 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_1) ... ok
test_timeline_anomaly_2021_10 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_10) ... ok
test_timeline_anomaly_2021_11 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_11) ... ok
test_timeline_anomaly_2021_12 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_12) ... ok
test_timeline_anomaly_2021_2 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_2) ... ok
test_timeline_anomaly_2021_3 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_3) ... ok
test_timeline_anomaly_2021_4 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_4) ... ok
test_timeline_anomaly_2021_5 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_5) ... ok
test_timeline_anomaly_2021_6 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_6) ... ok
test_timeline_anomaly_2021_7 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_7) ... ok
test_timeline_anomaly_2021_8 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_8) ... ok
test_timeline_anomaly_2021_9 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2021_9) ... ok
test_timeline_anomaly_2022_1 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_1) ... ok
test_timeline_anomaly_2022_10 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_10) ... ok
test_timeline_anomaly_2022_11 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_11) ... ok
test_timeline_anomaly_2022_12 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_12) ... ok
test_timeline_anomaly_2022_2 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_2) ... ok
test_timeline_anomaly_2022_3 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_3) ... ok
test_timeline_anomaly_2022_4 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_4) ... ok
test_timeline_anomaly_2022_5 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_5) ... ok
test_timeline_anomaly_2022_6 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_6) ... ok
test_timeline_anomaly_2022_7 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_7) ... ok
test_timeline_anomaly_2022_8 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_8) ... ok
test_timeline_anomaly_2022_9 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2022_9) ... ok
test_timeline_anomaly_2023_1 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_1) ... ok
test_timeline_anomaly_2023_10 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_10) ... ok
test_timeline_anomaly_2023_11 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_11) ... ok
test_timeline_anomaly_2023_12 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_12) ... ok
test_timeline_anomaly_2023_2 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_2) ... ok
test_timeline_anomaly_2023_3 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_3) ... ok
test_timeline_anomaly_2023_4 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_4) ... ok
test_timeline_anomaly_2023_5 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_5) ... ok
test_timeline_anomaly_2023_6 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_6) ... ok
test_timeline_anomaly_2023_7 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_7) ... ok
test_timeline_anomaly_2023_8 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_8) ... ok
test_timeline_anomaly_2023_9 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2023_9) ... ok
test_timeline_anomaly_2024_1 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_1) ... ok
test_timeline_anomaly_2024_10 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_10) ... ok
test_timeline_anomaly_2024_11 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_11) ... ok
test_timeline_anomaly_2024_12 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_12) ... ok
test_timeline_anomaly_2024_2 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_2) ... ok
test_timeline_anomaly_2024_3 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_3) ... ok
test_timeline_anomaly_2024_4 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_4) ... ok
test_timeline_anomaly_2024_5 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_5) ... ok
test_timeline_anomaly_2024_6 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_6) ... ok
test_timeline_anomaly_2024_7 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_7) ... ok
test_timeline_anomaly_2024_8 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_8) ... ok
test_timeline_anomaly_2024_9 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2024_9) ... ok
test_timeline_anomaly_2025_1 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_1) ... ok
test_timeline_anomaly_2025_10 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_10) ... ok
test_timeline_anomaly_2025_11 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_11) ... ok
test_timeline_anomaly_2025_12 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_12) ... ok
test_timeline_anomaly_2025_2 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_2) ... ok
test_timeline_anomaly_2025_3 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_3) ... ok
test_timeline_anomaly_2025_4 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_4) ... ok
test_timeline_anomaly_2025_5 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_5) ... ok
test_timeline_anomaly_2025_6 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_6) ... ok
test_timeline_anomaly_2025_7 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_7) ... ok
test_timeline_anomaly_2025_8 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_8) ... ok
test_timeline_anomaly_2025_9 (test_massive_matrix.TestMassiveForensicMatrix.test_timeline_anomaly_2025_9) ... ok

----------------------------------------------------------------------
Ran 621 tests in 0.124s

OK

```
