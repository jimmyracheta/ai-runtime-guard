import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import agent_configurator


class AgentConfiguratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
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

    def test_claude_apply_requires_mcp_without_auto_add(self) -> None:
        profile = {
            "profile_id": "p-claude",
            "agent_type": "claude_code",
            "workspace": str(self.workspace),
            "agent_id": "claude-code-1",
        }
        result = agent_configurator.apply_hardening(self.paths, profile, auto_add_mcp=False)
        self.assertFalse(result.get("ok"))
        self.assertTrue(result.get("requires_mcp"))

    def test_claude_apply_auto_add_mcp_and_undo(self) -> None:
        profile = {
            "profile_id": "p-claude",
            "agent_type": "claude_code",
            "workspace": str(self.workspace),
            "agent_id": "claude-code-1",
        }
        settings_local = self.workspace / ".claude" / "settings.local.json"
        settings_local.parent.mkdir(parents=True, exist_ok=True)
        original_settings = {
            "permissions": {
                "deny": ["Read"],
                "allow": ["Task"],
            },
            "sandbox": {
                "enabled": False,
                "allowUnsandboxedCommands": True,
            },
        }
        settings_local.write_text(json.dumps(original_settings, indent=2))

        applied = agent_configurator.apply_hardening(self.paths, profile, auto_add_mcp=True)
        self.assertTrue(applied.get("ok"), msg=applied)
        self.assertTrue(agent_configurator.undo_available(self.paths, "p-claude"))

        merged_settings = json.loads(settings_local.read_text())
        deny = merged_settings.get("permissions", {}).get("deny", [])
        self.assertIn("Bash", deny)
        self.assertIn("Write", deny)
        self.assertIn("Edit", deny)
        self.assertIn("MultiEdit", deny)
        self.assertIn("Read", deny)
        self.assertFalse(merged_settings.get("sandbox", {}).get("allowUnsandboxedCommands", True))
        self.assertTrue(merged_settings.get("sandbox", {}).get("enabled", False))

        workspace_mcp = self.workspace / ".mcp.json"
        self.assertTrue(workspace_mcp.exists())
        mcp_payload = json.loads(workspace_mcp.read_text())
        self.assertIn("ai-runtime-guard", mcp_payload.get("mcpServers", {}))
        mcp_env = mcp_payload["mcpServers"]["ai-runtime-guard"].get("env", {})
        self.assertEqual(set(mcp_env.keys()), {"AIRG_AGENT_ID", "AIRG_WORKSPACE"})

        undone = agent_configurator.undo_hardening(self.paths, profile)
        self.assertTrue(undone.get("ok"), msg=undone)
        self.assertFalse(agent_configurator.undo_available(self.paths, "p-claude"))
        self.assertEqual(json.loads(settings_local.read_text()), original_settings)
        self.assertFalse(workspace_mcp.exists())

    def test_cursor_apply_and_undo_restores_file(self) -> None:
        profile = {
            "profile_id": "p-cursor",
            "agent_type": "cursor",
            "workspace": str(self.workspace),
            "agent_id": "cursor-agent",
        }
        cursor_mcp = self.workspace / ".cursor" / "mcp.json"
        cursor_mcp.parent.mkdir(parents=True, exist_ok=True)
        original = {
            "mcpServers": {
                "existing": {
                    "command": "node",
                    "args": ["server.js"],
                }
            }
        }
        cursor_mcp.write_text(json.dumps(original, indent=2))

        applied = agent_configurator.apply_hardening(self.paths, profile)
        self.assertTrue(applied.get("ok"), msg=applied)

        merged = json.loads(cursor_mcp.read_text())
        self.assertIn("existing", merged.get("mcpServers", {}))
        self.assertIn("ai-runtime-guard", merged.get("mcpServers", {}))
        cursor_env = merged["mcpServers"]["ai-runtime-guard"].get("env", {})
        self.assertEqual(set(cursor_env.keys()), {"AIRG_AGENT_ID", "AIRG_WORKSPACE"})

        undone = agent_configurator.undo_hardening(self.paths, profile)
        self.assertTrue(undone.get("ok"), msg=undone)
        self.assertEqual(json.loads(cursor_mcp.read_text()), original)

    def test_claude_apply_accepts_local_scope_mcp_in_home_claude_json(self) -> None:
        profile = {
            "profile_id": "p-claude-local",
            "agent_type": "claude_code",
            "workspace": str(self.workspace),
            "agent_id": "claude-code-local",
        }
        settings_local = self.workspace / ".claude" / "settings.local.json"
        settings_local.parent.mkdir(parents=True, exist_ok=True)
        settings_local.write_text("{}\n")

        home_dir = self.base / "home"
        home_dir.mkdir(parents=True, exist_ok=True)
        claude_json = home_dir / ".claude.json"
        claude_json.write_text(
            json.dumps(
                {
                    "projects": {
                        str(self.workspace): {
                            "mcpServers": {
                                "ai-runtime-guard": {
                                    "command": "/tmp/airg-server",
                                    "args": [],
                                }
                            }
                        }
                    }
                },
                indent=2,
            )
        )

        with patch("agent_configurator.pathlib.Path.home", return_value=home_dir):
            applied = agent_configurator.apply_hardening(self.paths, profile, auto_add_mcp=False)
        self.assertTrue(applied.get("ok"), msg=applied)
        self.assertFalse(applied.get("requires_mcp"))
        self.assertIn("local", applied.get("preflight", {}).get("mcp_detected_scopes", []))
        self.assertFalse((self.workspace / ".mcp.json").exists())

    def test_claude_apply_scope_and_options_are_respected(self) -> None:
        profile = {
            "profile_id": "p-claude-options",
            "agent_type": "claude_code",
            "workspace": str(self.workspace),
            "agent_id": "claude-code-options",
            "agent_scope": "project",
        }
        mcp_file = self.workspace / ".mcp.json"
        mcp_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "ai-runtime-guard": {
                            "command": "airg-server",
                            "args": [],
                        }
                    }
                },
                indent=2,
            )
        )

        options = {
            "scope": "project",
            "hook_enabled": True,
            "restrict_native_tools": True,
            "native_tools": ["Bash", "Write"],
            "sandbox_enabled": False,
            "sandbox_escape_closed": False,
        }
        applied = agent_configurator.apply_hardening(self.paths, profile, options=options, auto_add_mcp=False)
        self.assertTrue(applied.get("ok"), msg=applied)
        target = self.workspace / ".claude" / "settings.json"
        self.assertTrue(target.exists())
        payload = json.loads(target.read_text())
        deny = payload.get("permissions", {}).get("deny", [])
        self.assertIn("Bash", deny)
        self.assertIn("Write", deny)
        self.assertNotIn("Read", deny)
        self.assertFalse(bool(payload.get("sandbox", {}).get("enabled", False)))


if __name__ == "__main__":
    unittest.main()
