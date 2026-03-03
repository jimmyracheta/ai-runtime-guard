import json
import os
import pathlib
import re
import tempfile
import unittest

import approvals
import backup
import policy_engine
from tools.command_tools import execute_command
from tools.file_tools import delete_file, list_directory, read_file, write_file

from tests.test_helpers import apply_test_environment, install_test_policy, reset_runtime_state, restore_policy


class AttackerTestSuite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = pathlib.Path(self.tmp.name)
        self.env_stack = apply_test_environment(self.workspace, max_retries=2)
        self.env_stack.__enter__()
        self.original_policy = install_test_policy()
        reset_runtime_state()

    def tearDown(self):
        restore_policy(self.original_policy)
        reset_runtime_state()
        self.env_stack.close()
        self.tmp.cleanup()

    def _write(self, relative: str, content: str = "x") -> pathlib.Path:
        target = self.workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def test_simulation_blocks_when_blast_radius_exceeds_threshold(self):
        self._write("a.log")
        self._write("b.log")
        self._write("c.log")

        result = policy_engine.check_policy("rm *.log")
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_tier, "requires_simulation")
        self.assertIn("blast radius is 3", result.reason)

    def test_simulation_allows_when_within_threshold(self):
        self._write("a.log")
        result = policy_engine.check_policy("rm *.log")
        self.assertTrue(result.allowed)

    def test_simulation_blocks_when_wildcard_unresolved(self):
        result = policy_engine.check_policy("rm *.somethingrandom")
        self.assertFalse(result.allowed)
        self.assertEqual(result.decision_tier, "requires_simulation")
        self.assertIn("could not be safely simulated", result.reason)

    def test_destructive_find_blocked_via_policy_command_pattern(self):
        policy_engine.POLICY["blocked"]["commands"] = ["find -delete"]
        blocked = execute_command("find . -type f -delete")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("find -delete", blocked.lower())

    def test_non_destructive_find_allowed(self):
        self._write("a.log")
        output = execute_command("find . -name '*.log'")
        self.assertIn("a.log", output)

    def test_xargs_rm_blocked_via_policy_command_pattern(self):
        policy_engine.POLICY["blocked"]["commands"] = ["xargs rm"]
        blocked = execute_command("printf 'a.tmp\\n' | xargs rm")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("xargs rm", blocked.lower())

    def test_looped_rm_blocked_via_policy_command_pattern(self):
        policy_engine.POLICY["blocked"]["commands"] = ["do rm"]
        blocked = execute_command("for f in *.tmp; do rm \"$f\"; done")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("do rm", blocked.lower())

    def test_confirmation_response_includes_simulation_context_for_threshold(self):
        self._write("c1.tmp")
        self._write("c2.tmp")
        self._write("c3.tmp")
        policy_engine.POLICY["requires_confirmation"]["commands"] = ["rm"]
        policy_engine.POLICY["requires_simulation"]["bulk_file_threshold"] = 2

        blocked = execute_command("rm *.tmp")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("explicit confirmation handshake", blocked)
        self.assertIn("Simulation context:", blocked)
        self.assertIn("blast radius is 3", blocked)

    def test_confirmation_response_includes_simulation_context_for_unresolved_wildcard(self):
        policy_engine.POLICY["requires_confirmation"]["commands"] = ["rm"]
        policy_engine.POLICY["requires_simulation"]["bulk_file_threshold"] = 2

        blocked = execute_command("rm *.definitelymissing")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("explicit confirmation handshake", blocked)
        self.assertIn("Simulation context:", blocked)
        self.assertIn("could not be safely simulated", blocked)

    def test_confirmation_handshake_via_out_of_band_approval(self):
        self._write("safe.txt", "hello")
        policy_engine.POLICY["requires_confirmation"]["commands"] = ["cat"]

        blocked = execute_command("cat safe.txt")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("approval_token=", blocked)

        token_match = re.search(r"approval_token=([a-f0-9]+)", blocked)
        self.assertIsNotNone(token_match)
        token = token_match.group(1)

        approved, reason, matched_rule = approvals.consume_command_approval(
            "cat safe.txt",
            token,
            source="test.operator",
        )
        self.assertTrue(approved, msg=reason or matched_rule)

        output = execute_command("cat safe.txt")
        self.assertEqual(output, "hello")

    def test_server_side_retry_enforcement_ignores_client_retry_count(self):
        policy_engine.POLICY["blocked"]["commands"] = ["dd"]

        first = execute_command("dd if=src of=dst", retry_count=0)
        second = execute_command("dd if=src of=dst", retry_count=0)

        self.assertIn("[POLICY BLOCK]", first)
        self.assertIn("Maximum retries reached (2/2)", second)

    def test_shell_control_characters_are_blocked(self):
        blocked = execute_command("echo ok\nuname")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("control characters", blocked)

    def test_shell_workspace_containment_enforce_blocks_outside_workspace(self):
        policy_engine.POLICY["execution"]["shell_workspace_containment"] = {
            "mode": "enforce",
            "exempt_commands": [],
            "log_paths": True,
        }
        blocked = execute_command("ls /etc")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("Shell workspace containment blocked", blocked)

    def test_shell_workspace_containment_monitor_allows_with_warning_logged(self):
        policy_engine.POLICY["execution"]["shell_workspace_containment"] = {
            "mode": "monitor",
            "exempt_commands": [],
            "log_paths": True,
        }
        output = execute_command("ls /etc")
        # Command can still execute in monitor mode.
        self.assertTrue(isinstance(output, str))

        log_path = self.workspace / "activity.log"
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        execute_entries = [entry for entry in lines if entry.get("tool") == "execute_command"]
        self.assertTrue(execute_entries)
        latest = execute_entries[-1]
        self.assertEqual(latest.get("policy_decision"), "allowed")
        self.assertIn("shell_containment_warning", latest)
        self.assertTrue(latest.get("shell_containment_offending_paths"))

    def test_backup_preserves_relative_paths_and_manifest(self):
        first = self._write("dir1/a.txt", "one")
        second = self._write("dir2/a.txt", "two")

        backup_location = pathlib.Path(backup.backup_paths([str(first), str(second)]))
        self.assertTrue((backup_location / "dir1" / "a.txt").exists())
        self.assertTrue((backup_location / "dir2" / "a.txt").exists())

        manifest_path = backup_location / "manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(len(manifest), 2)

    def test_backup_retention_cleanup_removes_old_backups(self):
        policy_engine.POLICY["audit"]["backup_retention_days"] = 1
        old_backup = pathlib.Path(backup.BACKUP_DIR) / "old"
        old_backup.mkdir(parents=True, exist_ok=True)
        old_ts = (os.path.getmtime(old_backup) - (3 * 24 * 60 * 60))
        os.utime(old_backup, (old_ts, old_ts))

        backup.backup_paths([])
        self.assertFalse(old_backup.exists())

    def test_file_tools_read_write_list_delete_flow(self):
        (self.workspace / "nested").mkdir(parents=True, exist_ok=True)
        write_result = write_file("nested/demo.txt", "hello world")
        self.assertIn("Successfully wrote", write_result)

        read_result = read_file("nested/demo.txt")
        self.assertEqual(read_result, "hello world")

        listing = list_directory("nested")
        self.assertIn("demo.txt", listing)

        delete_result = delete_file("nested/demo.txt")
        self.assertIn("Successfully deleted", delete_result)

    def test_runtime_protected_files_are_blocked_for_file_tools(self):
        # Create placeholder files; policy should still block access by protected path rule.
        (self.workspace / "approvals.db").write_text("placeholder")
        (self.workspace / "activity.log").write_text("placeholder")

        read_db = read_file("approvals.db")
        self.assertIn("[POLICY BLOCK]", read_db)
        self.assertIn("runtime state", read_db)

        write_db = write_file("approvals.db", "tamper")
        self.assertIn("[POLICY BLOCK]", write_db)
        self.assertIn("runtime state", write_db)

        read_log = read_file("activity.log")
        self.assertIn("[POLICY BLOCK]", read_log)
        self.assertIn("runtime state", read_log)

    def test_write_file_skips_backup_when_backup_disabled(self):
        self._write("demo.txt", "old")
        policy_engine.POLICY["audit"]["backup_enabled"] = False
        result = write_file("demo.txt", "new")
        self.assertIn("no content-change backup needed", result)

        log_path = self.workspace / "activity.log"
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        backup_events = [entry for entry in lines if entry.get("event") == "backup_created" and entry.get("tool") == "write_file"]
        self.assertEqual(backup_events, [])

    def test_delete_file_skips_backup_when_backup_disabled(self):
        self._write("gone.txt", "x")
        policy_engine.POLICY["audit"]["backup_enabled"] = False
        result = delete_file("gone.txt")
        self.assertIn("No content-change backup was needed", result)

        log_path = self.workspace / "activity.log"
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        backup_events = [entry for entry in lines if entry.get("event") == "backup_created" and entry.get("tool") == "delete_file"]
        self.assertEqual(backup_events, [])


if __name__ == "__main__":
    unittest.main()
