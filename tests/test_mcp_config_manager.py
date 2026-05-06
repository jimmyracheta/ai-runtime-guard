import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import agent_configs
import mcp_config_manager


class MCPConfigManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.home = self.base / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.paths = {
            "policy_path": self.base / "policy.json",
            "approval_db_path": self.base / "state" / "approvals.db",
            "approval_hmac_key_path": self.base / "state" / "approvals.db.hmac.key",
            "log_path": self.base / "state" / "activity.log",
            "reports_db_path": self.base / "state" / "reports.db",
        }
        self.paths["approval_db_path"].parent.mkdir(parents=True, exist_ok=True)
        self.paths["policy_path"].write_text("{}\n")
        self.paths["approval_hmac_key_path"].write_text("hmac\n")
        self.paths["log_path"].write_text("\n")
        self.paths["reports_db_path"].write_text("\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _upsert_desktop_profile(self) -> dict:
        profile = {
            "profile_id": "p-desktop",
            "name": "Claude Desktop 1",
            "agent_type": "claude_desktop",
            "workspace": str(self.workspace),
            "agent_id": "claude-desktop-1",
        }
        upsert = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(upsert.get("ok"), msg=upsert)
        return upsert.get("profile", profile)

    def test_apply_and_remove_claude_desktop_mcp_config(self) -> None:
        profile = self._upsert_desktop_profile()
        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            desktop_cfg = mcp_config_manager._claude_desktop_config_path()
        desktop_cfg.parent.mkdir(parents=True, exist_ok=True)
        desktop_cfg.write_text(json.dumps({"preferences": {"sidebarMode": "chat"}}, indent=2))

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            applied = mcp_config_manager.apply_mcp_config(self.paths, profile)
        self.assertTrue(applied.get("ok"), msg=applied)

        payload = json.loads(desktop_cfg.read_text())
        self.assertEqual(payload.get("preferences", {}).get("sidebarMode"), "chat")
        self.assertIn("ai-runtime-guard", payload.get("mcpServers", {}))
        env = payload["mcpServers"]["ai-runtime-guard"].get("env", {})
        self.assertEqual(set(env.keys()), {"AIRG_AGENT_ID", "AIRG_WORKSPACE"})
        self.assertIsNone(applied.get("settings_local"))
        self.assertEqual(str(applied.get("plan", {}).get("scope", "")), "desktop")

        updated_profile = applied.get("profile", profile)
        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            removed = mcp_config_manager.remove_applied_mcp(self.paths, updated_profile)
        self.assertTrue(removed.get("ok"), msg=removed)
        after_remove = json.loads(desktop_cfg.read_text())
        self.assertEqual(after_remove.get("preferences", {}).get("sidebarMode"), "chat")
        self.assertNotIn("ai-runtime-guard", after_remove.get("mcpServers", {}))

    def _upsert_codex_profile(self, scope: str) -> dict:
        profile = {
            "profile_id": f"p-codex-{scope}",
            "name": f"Codex {scope}",
            "agent_type": "codex",
            "agent_scope": scope,
            "workspace": str(self.workspace),
            "agent_id": "codex-1",
        }
        upsert = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(upsert.get("ok"), msg=upsert)
        return upsert.get("profile", profile)

    def test_apply_and_remove_codex_global_config(self) -> None:
        profile = self._upsert_codex_profile("global")
        target = self.home / ".codex" / "config.toml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('[mcp_servers.existing]\ncommand = "node"\n')

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            applied = mcp_config_manager.apply_mcp_config(self.paths, profile)
        self.assertTrue(applied.get("ok"), msg=applied)
        text = target.read_text()
        self.assertIn("[mcp_servers.existing]", text)
        self.assertIn("[mcp_servers.ai-runtime-guard]", text)
        self.assertIn("AIRG_AGENT_ID", text)
        self.assertIn("AIRG_WORKSPACE", text)
        self.assertEqual(str(applied.get("plan", {}).get("scope", "")), "global")

        updated_profile = applied.get("profile", profile)
        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            removed = mcp_config_manager.remove_applied_mcp(self.paths, updated_profile)
        self.assertTrue(removed.get("ok"), msg=removed)
        after_text = target.read_text()
        self.assertIn("[mcp_servers.existing]", after_text)
        self.assertNotIn("[mcp_servers.ai-runtime-guard]", after_text)

    def test_apply_codex_global_config_is_idempotent(self) -> None:
        profile = self._upsert_codex_profile("global")
        target = self.home / ".codex" / "config.toml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('[mcp_servers.existing]\ncommand = "node"\n')

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            first = mcp_config_manager.apply_mcp_config(self.paths, profile)
        self.assertTrue(first.get("ok"), msg=first)
        first_text = target.read_text()

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            second = mcp_config_manager.apply_mcp_config(self.paths, first.get("profile", profile))
        self.assertTrue(second.get("ok"), msg=second)
        self.assertEqual(target.read_text(), first_text)

    def test_apply_codex_project_config_creates_project_file(self) -> None:
        profile = self._upsert_codex_profile("project")
        target = self.workspace / ".codex" / "config.toml"
        home_target = self.home / ".codex" / "config.toml"

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            applied = mcp_config_manager.apply_mcp_config(self.paths, profile, manage_codex_trust=True)
        self.assertTrue(applied.get("ok"), msg=applied)
        self.assertTrue(target.exists())
        text = target.read_text()
        self.assertIn("[mcp_servers.ai-runtime-guard]", text)
        self.assertIn("AIRG_AGENT_ID", text)
        self.assertIn("AIRG_WORKSPACE", text)
        self.assertTrue(home_target.exists())
        trust_text = home_target.read_text()
        self.assertIn(f'[projects."{self.workspace}"]', trust_text)
        self.assertIn('trust_level = "trusted"', trust_text)
        self.assertTrue(bool(applied.get("profile", {}).get("last_applied", {}).get("codex_project_trust", {}).get("managed")))

    def test_apply_codex_project_config_without_trust_choice_requires_confirmation(self) -> None:
        profile = self._upsert_codex_profile("project")
        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            result = mcp_config_manager.apply_mcp_config(self.paths, profile)
        self.assertFalse(result.get("ok"))
        self.assertTrue(result.get("requires_trust_choice"))

    def test_remove_codex_project_config_can_restore_trust_state(self) -> None:
        profile = self._upsert_codex_profile("project")
        home_target = self.home / ".codex" / "config.toml"
        home_target.parent.mkdir(parents=True, exist_ok=True)
        home_target.write_text('[projects."/tmp/existing"]\ntrust_level = "trusted"\n')

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            applied = mcp_config_manager.apply_mcp_config(self.paths, profile, manage_codex_trust=True)
        self.assertTrue(applied.get("ok"), msg=applied)

        updated_profile = applied.get("profile", profile)
        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            removed = mcp_config_manager.remove_applied_mcp(self.paths, updated_profile, remove_codex_trust=True)
        self.assertTrue(removed.get("ok"), msg=removed)
        trust_text = home_target.read_text()
        self.assertNotIn(f'[projects."{self.workspace}"]', trust_text)
        self.assertIn('[projects."/tmp/existing"]', trust_text)

    def _upsert_cursor_profile(self, scope: str) -> dict:
        profile = {
            "profile_id": f"p-cursor-{scope}",
            "name": f"Cursor {scope}",
            "agent_type": "cursor",
            "agent_scope": scope,
            "workspace": str(self.workspace),
            "agent_id": "cursor-1",
        }
        upsert = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(upsert.get("ok"), msg=upsert)
        return upsert.get("profile", profile)

    def test_apply_and_remove_cursor_project_config(self) -> None:
        profile = self._upsert_cursor_profile("project")
        target = self.workspace / ".cursor" / "mcp.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"mcpServers": {"existing": {"command": "node"}}}, indent=2))

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            applied = mcp_config_manager.apply_mcp_config(self.paths, profile)
        self.assertTrue(applied.get("ok"), msg=applied)
        payload = json.loads(target.read_text())
        self.assertIn("existing", payload.get("mcpServers", {}))
        self.assertIn("ai-runtime-guard", payload.get("mcpServers", {}))
        self.assertEqual(str(applied.get("plan", {}).get("scope", "")), "project")

        updated_profile = applied.get("profile", profile)
        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            removed = mcp_config_manager.remove_applied_mcp(self.paths, updated_profile)
        self.assertTrue(removed.get("ok"), msg=removed)
        after = json.loads(target.read_text())
        self.assertIn("existing", after.get("mcpServers", {}))
        self.assertNotIn("ai-runtime-guard", after.get("mcpServers", {}))

    def test_apply_cursor_global_config_creates_home_file(self) -> None:
        profile = self._upsert_cursor_profile("global")
        target = self.home / ".cursor" / "mcp.json"

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            applied = mcp_config_manager.apply_mcp_config(self.paths, profile)
        self.assertTrue(applied.get("ok"), msg=applied)
        self.assertEqual(str(applied.get("plan", {}).get("scope", "")), "global")
        self.assertTrue(target.exists())
        payload = json.loads(target.read_text())
        self.assertIn("ai-runtime-guard", payload.get("mcpServers", {}))


if __name__ == "__main__":
    unittest.main()
