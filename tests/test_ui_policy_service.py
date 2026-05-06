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
            "allowed": {"paths_whitelist": [], "max_directory_depth": 5},
            "network": {
                "enforcement_mode": "off",
                "commands": [],
                "allowed_domains": [],
                "blocked_domains": [],
                "block_unknown_domains": False,
            },
            "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000},
            "backup_access": {"block_agent_tools": True},
            "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
            "audit": {"backup_enabled": True, "backup_on_content_change_only": True, "max_versions_per_file": 5, "backup_root": str(self.base / "backups"), "backup_retention_days": 30, "log_level": "verbose", "redact_patterns": []},
            "telemetry": {
                "enabled": True,
                "endpoint": "https://telemetry.runtime-guard.ai/v1/telemetry",
                "last_payload_generated_date": "",
                "last_payload_uploaded_at": "",
                "last_sent_date": "",
            },
            "script_sentinel": {
                "enabled": False,
                "mode": "match_original",
                "scan_mode": "exec_context",
                "max_scan_bytes": 1048576,
                "include_wrappers": True,
            },
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

    def test_validate_and_apply_round_trip_telemetry_toggle(self):
        original_policy_path = service.POLICY_PATH
        original_log_path = service.CHANGE_LOG_PATH
        try:
            service.POLICY_PATH = self.policy_path
            service.CHANGE_LOG_PATH = self.log_path
            candidate = json.loads(json.dumps(self.initial))
            candidate["telemetry"]["enabled"] = False
            ok, _details = service.validate_and_apply(candidate, actor="test")
            self.assertTrue(ok)
            saved = json.loads(self.policy_path.read_text())
            self.assertFalse(bool(saved.get("telemetry", {}).get("enabled", True)))
        finally:
            service.POLICY_PATH = original_policy_path
            service.CHANGE_LOG_PATH = original_log_path

    def test_all_known_commands_includes_policy_and_catalog(self):
        catalog = {
            "tabs": [
                {"id": "all", "commands": []},
                {"id": "misc", "commands": ["xargs", "cat"]},
            ]
        }
        commands = service.all_known_commands(self.initial, catalog)
        self.assertIn("dd", commands)
        self.assertIn("cat", commands)
        self.assertIn("xargs", commands)

    def test_set_command_override_round_trip(self):
        updated = service.set_command_override(
            self.initial,
            "git clone",
            retry=2,
        )
        ov = updated.get("ui_overrides", {}).get("commands", {}).get("git clone", {})
        self.assertEqual(ov.get("retry_override"), 2)

        cleared = service.set_command_override(updated, "git clone", retry=None)
        self.assertNotIn("git clone", cleared.get("ui_overrides", {}).get("commands", {}))

    def test_validate_policy_rejects_agent_override_that_loosens_blocked(self):
        candidate = json.loads(json.dumps(self.initial))
        candidate["agent_overrides"] = {
            "agent-a": {
                "policy": {
                    "blocked": {"commands": [], "paths": [], "extensions": []}
                }
            }
        }
        ok, details = service.validate_policy(candidate)
        self.assertFalse(ok)
        self.assertIn("cannot be less restrictive", details["errors"][0])

    def test_validate_policy_accepts_tightening_agent_override(self):
        candidate = json.loads(json.dumps(self.initial))
        candidate["agent_overrides"] = {
            "agent-a": {
                "policy": {
                    "blocked": {"commands": ["dd", "rm"], "paths": [], "extensions": []},
                    "network": {"enforcement_mode": "enforce"},
                }
            }
        }
        ok, details = service.validate_policy(candidate)
        self.assertTrue(ok, msg=details.get("errors"))


if __name__ == "__main__":
    unittest.main()
