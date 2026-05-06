import json
import os
import pathlib
import re
import tempfile
import unittest

import approvals
import backup
import config
import policy_engine
import script_sentinel
from tools.command_tools import execute_command
from tools.file_tools import delete_file, edit_file, list_directory, read_file, write_file
from tools.restore_tools import restore_backup

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

    def test_destructive_find_blocked_via_policy_command_pattern(self):
        policy_engine.POLICY["blocked"]["commands"] = ["find -delete"]
        blocked = execute_command("find . -type f -delete")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("find -delete", blocked.lower())

    def test_non_destructive_find_allowed(self):
        self._write("a.log")
        output = execute_command("find . -name '*.log'")
        self.assertIn("a.log", output)

    def test_write_file_extension_block_does_not_raise_nameerror(self):
        policy_engine.POLICY["blocked"]["extensions"] = [".pem"]
        blocked = write_file("secret.pem", "dummy")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn(".pem", blocked)

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

    def test_confirmation_response_includes_token_for_threshold_case(self):
        self._write("c1.tmp")
        self._write("c2.tmp")
        self._write("c3.tmp")
        policy_engine.POLICY["requires_confirmation"]["commands"] = ["rm"]

        blocked = execute_command("rm *.tmp")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("explicit confirmation handshake", blocked)
        self.assertIn("approval_token=", blocked)

    def test_confirmation_response_for_unresolved_wildcard(self):
        policy_engine.POLICY["requires_confirmation"]["commands"] = ["rm"]

        blocked = execute_command("rm *.definitelymissing")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("explicit confirmation handshake", blocked)
        self.assertIn("approval_token=", blocked)

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

    def test_dangerous_env_assignment_prefix_is_blocked(self):
        blocked = execute_command("LD_PRELOAD=/tmp/x.so echo hi")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("environment assignment", blocked.lower())

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
        self.assertTrue(all(str(item.get("manifest_sig", "")) for item in manifest))

    def test_restore_rejects_unsigned_manifest_entries(self):
        target = self._write("restore/unsigned.txt", "before")
        backup_location = pathlib.Path(backup.backup_paths([str(target)]))
        manifest_path = backup_location / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        self.assertTrue(manifest)
        manifest[0].pop("manifest_sig", None)
        manifest_path.write_text(json.dumps(manifest, indent=2))

        dry_run_result = restore_backup(str(backup_location), dry_run=True)
        token_match = re.search(r"restore_token=([a-f0-9]+)", dry_run_result)
        self.assertIsNotNone(token_match)
        token = token_match.group(1)

        target.write_text("mutated")
        apply_result = restore_backup(str(backup_location), dry_run=False, restore_token=token)
        self.assertIn("signature_failures=1", apply_result)
        self.assertEqual(target.read_text(), "mutated")

    def test_backup_retention_cleanup_removes_old_backups(self):
        policy_engine.POLICY["audit"]["backup_retention_days"] = 1
        old_backup = pathlib.Path(backup.BACKUP_DIR) / "old"
        old_backup.mkdir(parents=True, exist_ok=True)
        old_ts = (os.path.getmtime(old_backup) - (3 * 24 * 60 * 60))
        os.utime(old_backup, (old_ts, old_ts))

        backup.backup_paths([])
        self.assertFalse(old_backup.exists())

    def test_backup_handles_workspace_root_and_file_targets_without_collision(self):
        target = self._write("1.tmp", "x")
        backup_location = pathlib.Path(
            backup.backup_paths([str(self.workspace), str(target)])
        )
        self.assertTrue(backup_location.exists())
        self.assertTrue((backup_location / "1.tmp").exists())

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

    def test_edit_file_flow(self):
        self._write("nested/edit.txt", "alpha beta gamma")
        result = edit_file("nested/edit.txt", old_text="beta", new_text="BETA")
        self.assertIn("Successfully edited", result)
        self.assertEqual(read_file("nested/edit.txt"), "alpha BETA gamma")

    def test_edit_file_ambiguous_match_requires_replace_all(self):
        self._write("nested/ambiguous.txt", "x y x")
        result = edit_file("nested/ambiguous.txt", old_text="x", new_text="z")
        self.assertIn("matched 2 times", result)
        self.assertEqual(read_file("nested/ambiguous.txt"), "x y x")

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

    def test_execute_command_blocks_runtime_paths_even_with_quote_splitting(self):
        policy_engine.POLICY["blocked"]["commands"] = []
        policy_engine.POLICY["blocked"]["paths"] = ["approvals.db"]
        (self.workspace / "approvals.db").write_text("placeholder")

        blocked = execute_command("cat ./a\"\"pprovals.db")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("approvals.db", blocked.lower())

    def test_write_file_skips_backup_when_backup_disabled(self):
        self._write("demo.txt", "old")
        policy_engine.POLICY["audit"]["backup_enabled"] = False
        result = write_file("demo.txt", "new")
        self.assertIn("no content-change backup needed", result)

        log_path = self.workspace / "activity.log"
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        backup_events = [entry for entry in lines if entry.get("event") == "backup_created" and entry.get("tool") == "write_file"]
        self.assertEqual(backup_events, [])

    def test_edit_file_creates_backup_event_when_enabled(self):
        self._write("edit/backup.txt", "before")
        result = edit_file("edit/backup.txt", old_text="before", new_text="after")
        self.assertIn("Successfully edited", result)
        self.assertIn("backed up to", result)

        log_path = self.workspace / "activity.log"
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        backup_events = [entry for entry in lines if entry.get("event") == "backup_created" and entry.get("tool") == "edit_file"]
        self.assertTrue(backup_events)

    def test_delete_file_skips_backup_when_backup_disabled(self):
        self._write("gone.txt", "x")
        policy_engine.POLICY["audit"]["backup_enabled"] = False
        result = delete_file("gone.txt")
        self.assertIn("No content-change backup was needed", result)

        log_path = self.workspace / "activity.log"
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        backup_events = [entry for entry in lines if entry.get("event") == "backup_created" and entry.get("tool") == "delete_file"]
        self.assertEqual(backup_events, [])

    def test_script_sentinel_blocks_tagged_script_execution(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["blocked"]["commands"] = ["danger-cmd"]
        policy_engine.POLICY["requires_confirmation"]["commands"] = []
        (self.workspace / "sentinel").mkdir(parents=True, exist_ok=True)

        write_result = write_file("sentinel/block.sh", "danger-cmd\n")
        self.assertIn("Script Sentinel flagged content", write_result)

        blocked = execute_command("bash sentinel/block.sh")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("Script Sentinel preserved policy intent", blocked)

    def test_script_sentinel_flags_on_edit_file_and_blocks_execution(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["blocked"]["commands"] = ["danger-cmd"]
        policy_engine.POLICY["requires_confirmation"]["commands"] = []
        self._write("sentinel/edit.sh", "echo safe\n")

        edit_result = edit_file("sentinel/edit.sh", old_text="echo safe", new_text="danger-cmd")
        self.assertIn("Script Sentinel flagged content", edit_result)

        blocked = execute_command("bash sentinel/edit.sh")
        self.assertIn("[POLICY BLOCK]", blocked)
        self.assertIn("Script Sentinel preserved policy intent", blocked)

    def test_script_sentinel_flags_from_override_union_and_enforces_by_executor_policy(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["blocked"]["commands"] = []
        policy_engine.POLICY["requires_confirmation"]["commands"] = []
        policy_engine.POLICY["agent_overrides"] = {
            "agent-b": {"policy": {"blocked": {"commands": ["danger-cmd"]}}}
        }
        (self.workspace / "sentinel").mkdir(parents=True, exist_ok=True)

        write_result = write_file("sentinel/union.sh", "danger-cmd\n")
        self.assertIn("Script Sentinel flagged content", write_result)

        # Current executor policy allows this pattern (not blocked/requires_confirmation),
        # so Script Sentinel does not enforce in match_original mode.
        allowed = execute_command("bash sentinel/union.sh")
        self.assertNotIn("[POLICY BLOCK]", allowed)

        # Simulate a different executor policy where the same pattern is blocked.
        policy_engine.POLICY["blocked"]["commands"] = ["danger-cmd"]
        blocked = execute_command("bash sentinel/union.sh")
        self.assertIn("[POLICY BLOCK]", blocked)

    def test_script_sentinel_exec_context_mode_ignores_mention_only_matches(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["script_sentinel"]["scan_mode"] = "exec_context"
        policy_engine.POLICY["blocked"]["commands"] = ["mv"]
        (self.workspace / "sentinel").mkdir(parents=True, exist_ok=True)

        write_result = write_file("sentinel/notes.txt", "This document mentions mv in prose.\n")
        self.assertNotIn("Script Sentinel flagged content", write_result)

        artifacts = script_sentinel.list_flagged_artifacts(limit=20, offset=0)
        paths = {item.get("path", "") for item in artifacts.get("items", [])}
        self.assertNotIn(str((self.workspace / "sentinel" / "notes.txt").resolve()), paths)

    def test_script_sentinel_mentions_mode_flags_but_does_not_enforce_mentions(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["script_sentinel"]["scan_mode"] = "exec_context_plus_mentions"
        policy_engine.POLICY["blocked"]["commands"] = ["mv"]
        (self.workspace / "sentinel").mkdir(parents=True, exist_ok=True)

        write_result = write_file("sentinel/mention.py", "# note: mv appears in text only\nprint('ok')\n")
        self.assertIn("Script Sentinel flagged content", write_result)

        artifacts = script_sentinel.list_flagged_artifacts(limit=20, offset=0)
        target = next((item for item in artifacts.get("items", []) if item.get("path", "").endswith("/sentinel/mention.py")), None)
        self.assertIsNotNone(target)
        signatures = target.get("matched_signatures", [])
        self.assertTrue(any(sig.get("match_context") == "mention_only" for sig in signatures))
        self.assertFalse(any(bool(sig.get("enforceable")) for sig in signatures if sig.get("type") == "policy_command"))

        allowed = execute_command("python3 sentinel/mention.py")
        self.assertNotIn("[POLICY BLOCK]", allowed)

    def test_script_sentinel_stale_hash_not_enforced_after_external_overwrite(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["blocked"]["commands"] = ["danger-cmd"]
        (self.workspace / "sentinel").mkdir(parents=True, exist_ok=True)

        write_result = write_file("sentinel/stale.sh", "danger-cmd\n")
        self.assertIn("Script Sentinel flagged content", write_result)

        # Out-of-band overwrite bypasses write_file scan, but execute-time hash check
        # should treat this as unflagged content now.
        (self.workspace / "sentinel" / "stale.sh").write_text("echo safe\n")

        allowed = execute_command("bash sentinel/stale.sh")
        self.assertNotIn("[POLICY BLOCK]", allowed)

    def test_script_sentinel_dismiss_once_and_trust_persistent(self):
        policy_engine.POLICY["script_sentinel"]["enabled"] = True
        policy_engine.POLICY["script_sentinel"]["mode"] = "match_original"
        policy_engine.POLICY["blocked"]["commands"] = ["danger-cmd"]
        (self.workspace / "sentinel").mkdir(parents=True, exist_ok=True)

        write_file("sentinel/allow.sh", "danger-cmd\n")
        artifacts = script_sentinel.list_flagged_artifacts(limit=10, offset=0)
        target = next((item for item in artifacts.get("items", []) if item.get("path", "").endswith("/sentinel/allow.sh")), None)
        self.assertIsNotNone(target)
        content_hash = str(target.get("content_hash", ""))
        self.assertTrue(content_hash)

        once = script_sentinel.create_allowance(
            agent_id=str(config.AGENT_ID),
            content_hash=content_hash,
            allowance_type="once",
            reason="test one-time bypass",
            created_by="tests",
            ttl_seconds=600,
        )
        self.assertEqual(once["allowance_type"], "once")

        first = execute_command("bash sentinel/allow.sh")
        self.assertNotIn("[POLICY BLOCK]", first)
        second = execute_command("bash sentinel/allow.sh")
        self.assertIn("[POLICY BLOCK]", second)

        persistent = script_sentinel.create_allowance(
            agent_id=str(config.AGENT_ID),
            content_hash=content_hash,
            allowance_type="persistent",
            reason="test persistent trust",
            created_by="tests",
        )
        self.assertEqual(persistent["allowance_type"], "persistent")

        third = execute_command("bash sentinel/allow.sh")
        self.assertNotIn("[POLICY BLOCK]", third)


if __name__ == "__main__":
    unittest.main()
