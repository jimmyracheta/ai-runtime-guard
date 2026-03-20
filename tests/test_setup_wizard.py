import pathlib
import tempfile
import unittest

import airg_cli


class SetupWizardTests(unittest.TestCase):
    def test_merge_additional_workspaces_dedupes(self) -> None:
        policy = {"allowed": {"paths_whitelist": ["/a", "/b"]}}
        merged = airg_cli._merge_additional_workspaces(policy, ["/b", "/c"])
        self.assertEqual(merged["allowed"]["paths_whitelist"], ["/a", "/b", "/c"])

    def test_apply_backup_override(self) -> None:
        policy = {"audit": {"backup_root": "/old"}}
        updated = airg_cli._apply_backup_override(policy, "/new")
        self.assertEqual(updated["audit"]["backup_root"], "/new")

    def test_agent_config_payload_includes_required_env(self) -> None:
        paths = {
            "policy_path": pathlib.Path("/tmp/policy.json"),
            "approval_db_path": pathlib.Path("/tmp/approvals.db"),
            "approval_hmac_key_path": pathlib.Path("/tmp/approvals.db.hmac.key"),
            "log_path": pathlib.Path("/tmp/activity.log"),
        }
        payload = airg_cli._agent_config_payload("claude_desktop", "/tmp/ws", paths, "agent-claude")
        env = payload["mcpServers"]["ai-runtime-guard"]["env"]
        self.assertEqual(env["AIRG_AGENT_ID"], "agent-claude")
        self.assertEqual(env["AIRG_WORKSPACE"], "/tmp/ws")
        self.assertEqual(set(env.keys()), {"AIRG_AGENT_ID", "AIRG_WORKSPACE"})

    def test_secure_permissions_creates_non_empty_hmac_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            paths = {
                "config_dir": base / "cfg",
                "state_dir": base / "state",
                "policy_path": base / "cfg" / "policy.json",
                "approval_db_path": base / "state" / "approvals.db",
                "approval_hmac_key_path": base / "state" / "approvals.db.hmac.key",
                "log_path": base / "state" / "activity.log",
            }
            airg_cli._secure_permissions(paths)
            self.assertTrue(paths["approval_hmac_key_path"].exists())
            self.assertGreater(paths["approval_hmac_key_path"].stat().st_size, 0)

    def test_write_agent_config_outputs_creates_file(self) -> None:
        payload = {"hello": "world"}
        with tempfile.TemporaryDirectory() as tmp:
            out = airg_cli._write_agent_config_outputs("generic", payload, pathlib.Path(tmp))
            self.assertTrue(out.exists())
            self.assertIn("generic.mcp.json", str(out))


if __name__ == "__main__":
    unittest.main()
