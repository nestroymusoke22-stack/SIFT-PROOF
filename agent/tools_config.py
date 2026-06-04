

SIFT_PROOF_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "start_investigation",
            "description": (
                "CALL THIS FIRST. Initializes a new investigation. "
                "Clears previous evidence and sets up coverage tracking."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "image_path": {
                        "type": "string",
                        "description": "Full path to disk image (.dd, .E01, .raw) or 'TEST_MODE' for demo"
                    },
                    "case_type": {
                        "type": "string",
                        "enum": ["windows_compromise", "ransomware", "generic"],
                        "description": "Type of investigation"
                    }
                },
                "required": ["image_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_mft_timeline",
            "description": "Extract MFT (Master File Table) file system timeline. Records file create/modify/delete events. Covers: file_system_timeline category.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"}
                },
                "required": ["image_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_amcache",
            "description": "Extract AmCache execution records including SHA256 hashes of executed binaries. Proves what ran even if files deleted. Covers: execution_artifacts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"}
                },
                "required": ["image_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_prefetch",
            "description": "Extract Windows Prefetch records. Proves program execution. Has last run time and run count. Covers: execution_artifacts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"}
                },
                "required": ["image_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_evtx_events",
            "description": "Extract Windows Event Logs. Key IDs: 4688=process_create, 4624=logon, 4698=sched_task, 7045=new_service, 1102=log_cleared. Covers: user_activity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"},
                    "event_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Specific event IDs. Leave empty for all forensic IDs."
                    }
                },
                "required": ["image_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_registry_runkeys",
            "description": "Extract registry Run/RunOnce persistence keys. Most common malware persistence location. Covers: persistence_mechanisms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "image_path": {"type": "string"}
                },
                "required": ["image_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_evidence",
            "description": "Run a SELECT query against the evidence database to explore data before making claims. Only SELECT is allowed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "table": {
                        "type": "string",
                        "enum": ["mft_events", "amcache_entries", "prefetch_events",
                                 "evtx_events", "registry_runkeys"],
                        "description": "Table to query"
                    },
                    "sql_filter": {
                        "type": "string",
                        "description": "WHERE clause. Example: filename LIKE '%evil%'"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "description": "Max rows to return"
                    }
                },
                "required": ["table", "sql_filter"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_claim",
            "description": (
                "THE MOST IMPORTANT TOOL. Submit a forensic finding for mathematical verification. "
                "Python will run your SQL against the real evidence database. "
                "If SQL finds no rows: claim is REJECTED and you get the real data to revise. "
                "If timestamps are impossible: TEMPORAL_CONTRADICTION fires (anti-forensics). "
                "NEVER write a conclusion without calling this first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string", "description": "Human readable finding description"},
                    "evidence_table": {
                        "type": "string",
                        "enum": ["mft_events", "amcache_entries", "prefetch_events",
                                 "evtx_events", "registry_runkeys"]
                    },
                    "sql_filter": {
                        "type": "string",
                        "description": "WHERE clause proving the claim. String values need single quotes."
                    },
                    "expected_result": {
                        "type": "string",
                        "enum": ["at_least_one_row", "no_rows"],
                        "description": "at_least_one_row for positive evidence, no_rows for absence claims"
                    },
                    "mitre_technique": {
                        "type": "string",
                        "description": "MITRE ATT&CK ID e.g. T1059.001"
                    }
                },
                "required": ["claim", "evidence_table", "sql_filter", "expected_result"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_coverage_status",
            "description": "Check investigation progress. Shows which mandatory categories are covered. Call before conclude_investigation.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "conclude_investigation",
            "description": "Finalize investigation and generate report. WILL FAIL if mandatory categories not covered. Check get_coverage_status first.",
            "parameters": {
                "type": "object",
                "properties": {
                    "analyst_summary": {
                        "type": "string",
                        "description": "Your final analysis, timeline of attack, and recommendations"
                    }
                },
                "required": ["analyst_summary"]
            }
        }
    }
]