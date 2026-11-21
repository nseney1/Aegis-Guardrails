"""Tests for GitHub Issue #77: Pre-seed Active File Constraints to Prevent Post-Generation Rejection Waste.

Ensures aegis_scan and the scan service (aegis_core.scan) extract target file constraints
prior to code generation, formatting an early-warning constraint summary at
the top of JIT prompt context and returning structured invariant_warnings.
"""
import os
import tempfile
import unittest

from aegis_core import scan as scan_service
from aegis_mcp.handlers.core import handle_scan


class TestJitPreseedConstraints(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = self.temp_dir.name
        self.rules_dir = os.path.join(self.workspace, ".aegis", "rules")
        for sub in ("invariants", "traps"):
            os.makedirs(os.path.join(self.rules_dir, sub), exist_ok=True)

        # Create a sample invariant rule (security invariant)
        invariant_rule = (
            "---\n"
            "name: auth-token-invariants\n"
            "type: invariant\n"
            "enforcement: gate\n"
            "target_paths:\n"
            '  - "aegis_core/*.py"\n'
            "hypothesis: Never store secrets in plain-text or bypass auth token validation\n"
            "prediction: Token validation bypass will allow unauthorized access\n"
            "---\n"
            "# Auth Token Invariants\n"
            "All authentication handlers must validate tokens before processing requests.\n"
        )
        with open(os.path.join(self.rules_dir, "invariants", "auth-token-invariants.md"), "w", encoding="utf-8") as f:
            f.write(invariant_rule)

        # Create a sample trap rule (anti-pattern trap)
        trap_rule = (
            "---\n"
            "name: no-broad-exceptions\n"
            "type: trap\n"
            "enforcement: advisory\n"
            "target_paths:\n"
            '  - "aegis_core/*.py"\n'
            "hypothesis: Broad except Exception blocks swallow critical system faults\n"
            "prediction: Silent failure during runtime\n"
            "---\n"
            "# No Broad Exceptions\n"
            "Catch specific exceptions rather than broad Exception.\n"
        )
        with open(os.path.join(self.rules_dir, "traps", "no-broad-exceptions.md"), "w", encoding="utf-8") as f:
            f.write(trap_rule)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_express_returns_structured_invariant_warnings(self):
        """express() should extract structured invariant_warnings for candidate files."""
        result = scan_service.scan(
            self.workspace,
            changed_files=["aegis_core/auth.py"],
        )
        self.assertIn("invariant_warnings", result)
        constraints = result["invariant_warnings"]
        self.assertIsInstance(constraints, list)
        self.assertGreaterEqual(len(constraints), 1)

        # Check constraint fields
        invariant_constraints = [c for c in constraints if c.get("type") == "invariant"]
        self.assertTrue(len(invariant_constraints) >= 1)
        invariant = invariant_constraints[0]
        self.assertIn("name", invariant)
        self.assertIn("hypothesis", invariant)
        self.assertIn("Never store secrets", invariant["hypothesis"])

    def test_early_warning_summary_at_top_of_guidance(self):
        """express() should format an early-warning constraint section at the top of guidance."""
        result = scan_service.scan(
            self.workspace,
            changed_files=["aegis_core/auth.py"],
        )
        context = result.get("guidance", "")
        # Must contain an early-warning constraint header
        self.assertIn("## Pre-Edit Invariants & Constraints", context)

        # Early-warning section must appear before general active rules
        early_warning_pos = context.find("## Pre-Edit Invariants & Constraints")
        active_rules_pos = context.find("## Active Governance Rules")
        if active_rules_pos != -1:
            self.assertLess(
                early_warning_pos,
                active_rules_pos,
                "Early-warning constraints must appear before active rules to anchor LLM attention",
            )

        # The warning must cite the invariant
        self.assertIn("Never store secrets in plain-text", context)

    def test_scan_handler_exposes_invariant_warnings(self):
        """MCP handle_scan should return invariant_warnings in its result."""
        args = {
            "workspace": self.workspace,
            "files": ["aegis_core/auth.py"],
        }
        res = handle_scan(args)
        self.assertNotIn("error", res)
        self.assertEqual([w["name"] for w in res["invariant_warnings"]], ["auth-token-invariants"])
        self.assertIn("## Pre-Edit Invariants & Constraints", res["guidance"])

    def test_preseed_inspection_with_unmodified_target_file(self):
        """Agent should be able to inspect constraints for a target file before editing it."""
        # Note: aegis_core/auth.py does NOT need to exist or be dirty in git
        result = scan_service.scan(
            self.workspace,
            changed_files=["aegis_core/new_handler.py"],
        )
        self.assertGreaterEqual(len(result["invariant_warnings"]), 1)
        self.assertIn("Never store secrets", result["guidance"])
