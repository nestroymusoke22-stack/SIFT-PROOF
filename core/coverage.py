

COVERAGE_MATRIX = {
    "windows_compromise": {
        "mandatory": [
            "execution_artifacts",
            "persistence_mechanisms",
            "file_system_timeline",
            "user_activity",
        ],
        "optional": ["network_indicators", "memory_artifacts"],
        "tool_to_category": {
            "get_mft_timeline": "file_system_timeline",
            "get_amcache": "execution_artifacts",
            "get_prefetch": "execution_artifacts",
            "get_evtx_events": "user_activity",
            "get_registry_runkeys": "persistence_mechanisms",
        }
    },
    "ransomware": {
        "mandatory": [
            "execution_artifacts", "file_system_timeline",
            "persistence_mechanisms", "user_activity",
        ],
        "optional": ["network_indicators"],
        "tool_to_category": {
            "get_mft_timeline": "file_system_timeline",
            "get_amcache": "execution_artifacts",
            "get_prefetch": "execution_artifacts",
            "get_evtx_events": "user_activity",
            "get_registry_runkeys": "persistence_mechanisms",
        }
    },
    "generic": {
        "mandatory": ["execution_artifacts", "file_system_timeline"],
        "optional": ["persistence_mechanisms", "user_activity"],
        "tool_to_category": {
            "get_mft_timeline": "file_system_timeline",
            "get_amcache": "execution_artifacts",
            "get_prefetch": "execution_artifacts",
            "get_evtx_events": "user_activity",
            "get_registry_runkeys": "persistence_mechanisms",
        }
    }
}

_tracker = None


class CoverageTracker:
    def __init__(self, case_type="generic"):
        config = COVERAGE_MATRIX.get(case_type, COVERAGE_MATRIX["generic"])
        self.case_type = case_type
        self.mandatory = config["mandatory"]
        self.optional = config.get("optional", [])
        self.tool_map = config["tool_to_category"]
        self.covered = set()
        self.tools_called = []
        print(f"[COVERAGE] Initialized: {case_type}")
        print(f"[COVERAGE] Mandatory: {self.mandatory}")

    def record_tool(self, tool_name):
        self.tools_called.append(tool_name)
        category = self.tool_map.get(tool_name)
        if category and category not in self.covered:
            self.covered.add(category)
            print(f"[COVERAGE] ✓ Covered: {category}")

    def report(self):
        missing = [c for c in self.mandatory if c not in self.covered]
        covered_mandatory = [c for c in self.mandatory if c in self.covered]
        pct = int(len(covered_mandatory) / len(self.mandatory) * 100) if self.mandatory else 100
        return {
            "coverage_percentage": pct,
            "mandatory_covered": covered_mandatory,
            "mandatory_missing": missing,
            "optional_covered": [c for c in self.optional if c in self.covered],
            "tools_called": self.tools_called,
            "is_complete": len(missing) == 0
        }

    def assert_complete(self):
        r = self.report()
        if r["is_complete"]:
            return True
        missing = r["mandatory_missing"]
        tool_hints = []
        for cat in missing:
            tools = [t for t, c in self.tool_map.items() if c == cat]
            tool_hints.append(f"  - {cat}: call {' or '.join(tools)}")
        raise ValueError(
            f"\n{'='*55}\n"
            f"CANNOT CONCLUDE — INVESTIGATION INCOMPLETE\n"
            f"{'='*55}\n"
            f"Coverage: {r['coverage_percentage']}% "
            f"({len(r['mandatory_covered'])}/{len(self.mandatory)} mandatory)\n\n"
            f"Missing mandatory categories:\n" + "\n".join(tool_hints) +
            f"\n\nRun the tools above before calling conclude_investigation.\n"
            f"{'='*55}"
        )


def initialize_coverage(case_type="generic"):
    global _tracker
    _tracker = CoverageTracker(case_type)
    return _tracker.report()


def record_tool_call(tool_name):
    if _tracker:
        _tracker.record_tool(tool_name)


def get_coverage_report():
    if not _tracker:
        return {"error": "No investigation started. Call start_investigation first."}
    return _tracker.report()


def check_can_conclude():
    if not _tracker:
        raise ValueError("No investigation initialized.")
    return _tracker.assert_complete()