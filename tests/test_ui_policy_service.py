import json
import pathlib
import tempfile
import unittest

from ui import service


class UIPolicyServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.policy_path = self.base / "policy.json"
        self.log_path = self.base / "changes.log"
        self.initial = {
            "blocked": {"commands": ["dd"], "paths": [], "extensions": []},
            "requires_confirmation": {
                "commands": ["cat"],
                "paths": [],
                "session_whitelist_enabled": True,
                "approval_security": {"max_failed_attempts_per_token": 5, "failed_attempt_window_seconds": 600, "token_ttl_seconds": 600},
            },
            "requires_simulation": {
                "commands": ["rm"],
                "bulk_file_threshold": 10,
                "max_retries": 3,
                "cumulative_budget": {
                    "enabled": True,
                    "scope": "session",
                    "limits": {"max_unique_paths": 50, "max_total_operations": 100, "max_total_bytes_estimate": 104857600},
                    "counting": {"mode": "affected_paths", "dedupe_paths": True, "include_noop_attempts": False, "commands_included": ["rm"]},
                    "reset": {"mode": "sliding_window", "window_seconds": 3600, "idle_reset_seconds": 900, "reset_on_server_restart": True},
                    "on_exceed": {"decision_tier": "blocked", "matched_rule": "requires_simulation.cumulative_budget_exceeded", "message": "x"},
                    "overrides": {"enabled": True, "require_confirmation_tool": "approve_command", "token_ttl_seconds": 300, "max_override_actions": 1, "audit_reason_required": True, "allowed_roles": ["human-operator"]},
                    "audit": {"log_budget_state": True, "fields": ["budget_scope"]},
                },
            },
            "allowed": {"paths_whitelist": [], "max_files_per_operation": 10, "max_file_size_mb": 10, "max_directory_depth": 5},
            "network": {"enforcement_mode": "off", "commands": [], "allowed_domains": [], "blocked_domains": [], "max_payload_size_kb": 1024},
            "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000},
            "backup_access": {"block_agent_tools": True, "allowed_tools": ["restore_backup"]},
            "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
            "audit": {"backup_enabled": True, "backup_on_content_change_only": True, "max_versions_per_file": 5, "backup_root": str(self.base / "backups"), "backup_retention_days": 30, "log_level": "verbose", "redact_patterns": []},
        }
        self.policy_path.write_text(json.dumps(self.initial))

    def tearDown(self):
        self.tmp.cleanup()

    def test_apply_tier_command_moves_command_between_tiers(self):
        updated = service.apply_tier_command(self.initial, "cat", "blocked")
        self.assertIn("cat", updated["blocked"]["commands"])
        self.assertNotIn("cat", updated["requires_confirmation"]["commands"])

    def test_validate_policy_accepts_valid_candidate(self):
        ok, details = service.validate_policy(self.initial)
        self.assertTrue(ok)
        self.assertIsInstance(details["normalized"], dict)

    def test_validate_and_apply_writes_policy_and_log(self):
        original_policy_path = service.POLICY_PATH
        original_log_path = service.CHANGE_LOG_PATH
        try:
            service.POLICY_PATH = self.policy_path
            service.CHANGE_LOG_PATH = self.log_path
            candidate = service.apply_tier_command(self.initial, "git clone", "requires_confirmation")
            ok, details = service.validate_and_apply(candidate, actor="test")
            self.assertTrue(ok)
            self.assertTrue(details["applied"])
            saved = json.loads(self.policy_path.read_text())
            self.assertIn("git clone", saved["requires_confirmation"]["commands"])
            log_lines = self.log_path.read_text().strip().splitlines()
            self.assertEqual(len(log_lines), 1)
        finally:
            service.POLICY_PATH = original_policy_path
            service.CHANGE_LOG_PATH = original_log_path


if __name__ == "__main__":
    unittest.main()
