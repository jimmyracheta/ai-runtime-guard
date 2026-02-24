import copy
import datetime
import json
import os
import pathlib
import re
import sys
import tempfile
import types
import unittest

# Minimal stub so tests can import server.py without installing MCP.
if "mcp.server.fastmcp" not in sys.modules:
    mcp_mod = types.ModuleType("mcp")
    mcp_server_mod = types.ModuleType("mcp.server")
    mcp_fastmcp_mod = types.ModuleType("mcp.server.fastmcp")

    class FastMCP:
        def __init__(self, _name):
            pass

        def tool(self):
            def decorator(func):
                return func
            return decorator

        def run(self):
            return None

    mcp_fastmcp_mod.FastMCP = FastMCP
    sys.modules["mcp"] = mcp_mod
    sys.modules["mcp.server"] = mcp_server_mod
    sys.modules["mcp.server.fastmcp"] = mcp_fastmcp_mod

import server


class AttackerTestSuite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = pathlib.Path(self.tmp.name)

        self.orig_policy = copy.deepcopy(server.POLICY)
        self.orig_max_retries = server.MAX_RETRIES
        self.orig_workspace = server.WORKSPACE_ROOT
        self.orig_log = server.LOG_PATH
        self.orig_backup = server.BACKUP_DIR

        server.WORKSPACE_ROOT = str(self.workspace)
        server.LOG_PATH = str(self.workspace / "activity.log")
        server.BACKUP_DIR = str(self.workspace / "backups")

        server.SESSION_WHITELIST.clear()
        server.PENDING_APPROVALS.clear()
        server.SERVER_RETRY_COUNTS.clear()

        server.POLICY = {
            "blocked": {
                "commands": [],
                "paths": [],
                "extensions": [],
            },
            "requires_confirmation": {
                "commands": [],
                "paths": [],
                "session_whitelist_enabled": True,
            },
            "requires_simulation": {
                "commands": ["rm", "mv"],
                "bulk_file_threshold": 2,
                "max_retries": 2,
                "cumulative_budget": {
                    "enabled": False,
                    "scope": "session",
                    "limits": {
                        "max_unique_paths": 50,
                        "max_total_operations": 100,
                        "max_total_bytes_estimate": 104857600,
                    },
                    "counting": {
                        "mode": "affected_paths",
                        "dedupe_paths": True,
                        "include_noop_attempts": False,
                        "commands_included": ["rm", "mv", "write_file", "delete_file"],
                    },
                    "reset": {
                        "mode": "sliding_window",
                        "window_seconds": 3600,
                        "idle_reset_seconds": 900,
                        "reset_on_server_restart": True,
                    },
                    "on_exceed": {
                        "decision_tier": "blocked",
                        "matched_rule": "requires_simulation.cumulative_budget_exceeded",
                        "message": "Cumulative blast-radius budget exceeded for current scope.",
                    },
                    "overrides": {
                        "enabled": False,
                        "require_confirmation_tool": "approve_command",
                        "token_ttl_seconds": 300,
                        "max_override_actions": 1,
                        "audit_reason_required": True,
                        "allowed_roles": ["human-operator"],
                    },
                    "audit": {
                        "log_budget_state": True,
                        "fields": [
                            "budget_scope",
                            "budget_key",
                            "cumulative_unique_paths",
                            "cumulative_total_operations",
                            "cumulative_total_bytes_estimate",
                            "budget_remaining",
                        ],
                    },
                },
            },
            "allowed": {
                "paths_whitelist": [],
                "max_files_per_operation": 10,
                "max_file_size_mb": 10,
                "max_directory_depth": 20,
            },
            "network": {
                "enforcement_mode": "off",
                "commands": ["curl", "wget", "http", "https"],
                "allowed_domains": [],
                "blocked_domains": [],
                "max_payload_size_kb": 1024,
            },
            "execution": {
                "max_command_timeout_seconds": 30,
                "max_output_chars": 200000,
            },
            "backup_access": {
                "block_agent_tools": True,
                "allowed_tools": ["restore_backup"],
            },
            "restore": {
                "require_dry_run_before_apply": True,
                "confirmation_ttl_seconds": 300,
            },
            "audit": {
                "backup_enabled": True,
                "backup_on_content_change_only": True,
                "max_versions_per_file": 5,
                "backup_retention_days": 30,
                "log_level": "verbose",
                "redact_patterns": [],
            },
        }
        server.MAX_RETRIES = 2

    def tearDown(self):
        server.POLICY = self.orig_policy
        server.MAX_RETRIES = self.orig_max_retries
        server.WORKSPACE_ROOT = self.orig_workspace
        server.LOG_PATH = self.orig_log
        server.BACKUP_DIR = self.orig_backup

        server.SESSION_WHITELIST.clear()
        server.PENDING_APPROVALS.clear()
        server.SERVER_RETRY_COUNTS.clear()
        server.CUMULATIVE_BUDGET_STATE.clear()
        server.APPROVAL_FAILURES.clear()
        server.PENDING_RESTORE_CONFIRMATIONS.clear()
        self.tmp.cleanup()

    def _write(self, relative: str, content: str = "x") -> pathlib.Path:
        p = self.workspace / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def test_simulation_blocks_when_blast_radius_exceeds_threshold(self):
        self._write("a.log")
        self._write("b.log")
        self._write("c.log")

        result = server.check_policy("rm *.log")
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_tier, "requires_simulation")
        self.assertIn("blast radius is 3", result.reason)

    def test_simulation_allows_when_within_threshold(self):
        self._write("a.log")

        result = server.check_policy("rm *.log")
        self.assertTrue(result.allowed)

    def test_simulation_blocks_when_wildcard_unresolved(self):
        result = server.check_policy("rm *.somethingrandom")
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_tier, "requires_simulation")
        self.assertIn("could not be safely simulated", result.reason)

    def test_confirmation_handshake_and_approve_command(self):
        server.POLICY["requires_confirmation"]["commands"] = ["cat"]
        self._write("safe.txt", "hello")

        blocked = server.execute_command("cat safe.txt")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("approval_token=", blocked)

        token = re.search(r"approval_token=([a-f0-9]+)", blocked).group(1)
        approved = server.approve_command("cat safe.txt", token)
        self.assertIn("approved", approved.lower())

        output = server.execute_command("cat safe.txt")
        self.assertEqual(output, "hello")

    def test_server_side_retry_enforcement_ignores_client_retry_count(self):
        server.POLICY["blocked"]["commands"] = ["dd"]

        first = server.execute_command("dd if=src of=dst", retry_count=0)
        second = server.execute_command("dd if=src of=dst", retry_count=0)

        self.assertIn("[POLICY BLOCK]", first)
        self.assertIn("Maximum retries reached (2/2)", second)

    def test_shell_control_characters_are_blocked(self):
        blocked = server.execute_command("echo ok\nuname")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("control characters", blocked)

    def test_backup_preserves_relative_paths_and_manifest(self):
        first = self._write("dir1/a.txt", "one")
        second = self._write("dir2/a.txt", "two")

        backup_location = pathlib.Path(server.backup_paths([str(first), str(second)]))
        self.assertTrue((backup_location / "dir1" / "a.txt").exists())
        self.assertTrue((backup_location / "dir2" / "a.txt").exists())

        manifest_path = backup_location / "manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(len(manifest), 2)

    def test_backup_retention_cleanup_removes_old_backups(self):
        server.POLICY["audit"]["backup_retention_days"] = 1
        old_backup = pathlib.Path(server.BACKUP_DIR) / "old"
        old_backup.mkdir(parents=True, exist_ok=True)

        old_ts = (datetime.datetime.utcnow() - datetime.timedelta(days=3)).timestamp()
        os.utime(old_backup, (old_ts, old_ts))

        server.backup_paths([])
        self.assertFalse(old_backup.exists())

    def test_restore_backup_restores_previous_file_content(self):
        target = self._write("restore_me.txt", "before")
        backup_location = server.backup_paths([str(target)])
        target.write_text("after")

        dry = server.restore_backup(backup_location, dry_run=True)
        token = re.search(r"restore_token=([a-f0-9]+)", dry).group(1)
        restore_result = server.restore_backup(backup_location, dry_run=False, restore_token=token)
        self.assertIn("restored=1", restore_result)
        self.assertEqual(target.read_text(), "before")

    def test_restore_backup_requires_dry_run_token(self):
        target = self._write("restore_token.txt", "v1")
        backup_location = server.backup_paths([str(target)])
        target.write_text("v2")

        blocked = server.restore_backup(backup_location, dry_run=False)
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("restore token", blocked.lower())

    def test_backup_dedup_skips_unchanged_content(self):
        target = self._write("same.txt", "stable")
        first = server.backup_paths([str(target)])
        second = server.backup_paths([str(target)])
        self.assertTrue(first)
        self.assertEqual(second, "")

    def test_backup_max_versions_per_file_prunes_old_entries(self):
        server.POLICY["audit"]["max_versions_per_file"] = 2
        target = self._write("versioned.txt", "v1")
        server.backup_paths([str(target)])
        target.write_text("v2")
        server.backup_paths([str(target)])
        target.write_text("v3")
        server.backup_paths([str(target)])

        entries = server._backup_entries_for_source(target)
        self.assertLessEqual(len(entries), 2)

    def test_backup_storage_is_protected_from_file_tools(self):
        target = self._write("protect.txt", "x")
        backup_location = pathlib.Path(server.backup_paths([str(target)]))
        backup_file = next(backup_location.glob("protect.txt"))
        blocked = server.read_file(str(backup_file))
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("protected backup storage", blocked)

    def test_backup_storage_is_protected_from_execute_command(self):
        target = self._write("protect_cmd.txt", "x")
        backup_location = pathlib.Path(server.backup_paths([str(target)]))
        blocked = server.execute_command(f"ls -la {backup_location}")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("protected backup storage", blocked)

    def test_cumulative_budget_blocks_multi_step_bypass(self):
        server.POLICY["requires_simulation"]["bulk_file_threshold"] = 10
        server.POLICY["requires_simulation"]["cumulative_budget"]["enabled"] = True
        server.POLICY["requires_simulation"]["cumulative_budget"]["limits"]["max_unique_paths"] = 3
        server.POLICY["requires_simulation"]["cumulative_budget"]["counting"]["commands_included"] = ["rm"]
        server.MAX_RETRIES = 5

        self._write("a.log")
        self._write("b.log")
        self._write("c.log")
        self._write("d.log")

        first = server.execute_command("rm a.log b.log")
        second = server.execute_command("rm c.log d.log")

        self.assertNotIn("[POLICY BLOCK]", first)
        self.assertIn("[POLICY BLOCK]", second)
        self.assertIn("Cumulative blast-radius budget exceeded", second)
        self.assertTrue((self.workspace / "c.log").exists())
        self.assertTrue((self.workspace / "d.log").exists())

    def test_network_policy_enforcement_blocks_disallowed_domain(self):
        server.POLICY["network"]["enforcement_mode"] = "enforce"
        server.POLICY["network"]["blocked_domains"] = ["example.com"]

        result = server.execute_command("curl https://example.com")
        self.assertIn("[POLICY BLOCK]", result)
        self.assertIn("Network domain", result)

    def test_list_directory_depth_is_workspace_relative(self):
        nested = self.workspace / "one" / "two"
        nested.mkdir(parents=True)
        server.POLICY["allowed"]["max_directory_depth"] = 2

        result = server.list_directory(".")
        self.assertNotIn("[POLICY BLOCK]", result)

    def test_blocked_destructive_command_with_tilde_is_rejected(self):
        server.POLICY["blocked"]["commands"] = ["rm -rf ~"]
        result = server.execute_command("rm -rf ~")
        self.assertIn("[POLICY BLOCK]", result)
        self.assertIn("rm -rf ~", result.lower())

    def test_blocked_command_detected_inside_chained_expression(self):
        server.POLICY["blocked"]["commands"] = ["rm -rf"]
        result = server.execute_command("echo safe; RM -RF /tmp/x")
        self.assertIn("[POLICY BLOCK]", result)
        self.assertIn("rm -rf", result.lower())

    def test_semicolon_inside_quotes_does_not_trigger_false_split(self):
        server.POLICY["blocked"]["commands"] = ["rm -rf"]
        result = server.check_policy("echo 'literal ; text'")
        self.assertTrue(result.allowed)

    def test_requires_confirmation_for_curl(self):
        server.POLICY["requires_confirmation"]["commands"] = ["curl"]
        blocked = server.execute_command("curl https://example.com")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("approval_token=", blocked)

    def test_simulation_applies_to_cp_wildcards(self):
        server.POLICY["requires_simulation"]["commands"] = ["cp"]
        server.POLICY["requires_simulation"]["bulk_file_threshold"] = 1
        self._write("cp1.txt", "1")
        self._write("cp2.txt", "2")
        self._write("dest.txt", "")

        result = server.check_policy("cp *.txt dest.txt")
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_tier, "requires_simulation")

    def test_simulation_handles_escaped_wildcard_pattern(self):
        server.POLICY["requires_simulation"]["commands"] = ["rm"]
        server.POLICY["requires_simulation"]["bulk_file_threshold"] = 1
        self._write("e1.tmp", "1")
        self._write("e2.tmp", "2")

        result = server.check_policy(r"rm \*.tmp")
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_tier, "requires_simulation")


if __name__ == "__main__":
    unittest.main()
