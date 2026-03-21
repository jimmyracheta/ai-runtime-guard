import pathlib
import tempfile
import unittest

import agent_configs


class AgentConfigsTests(unittest.TestCase):
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
        }
        self.paths["approval_db_path"].parent.mkdir(parents=True, exist_ok=True)
        self.paths["policy_path"].write_text("{}\n")
        self.paths["approval_hmac_key_path"].write_text("hmac\n")
        self.paths["log_path"].write_text("\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_upsert_normalizes_scope_by_agent_type(self) -> None:
        profile = {
            "profile_id": "p-scope",
            "name": "Scope test",
            "agent_type": "claude_code",
            "agent_scope": "not-valid",
            "workspace": str(self.workspace),
            "agent_id": "claude-scope-1",
        }
        result = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(result.get("ok"), msg=result)
        saved = result.get("profile", {})
        self.assertEqual(saved.get("agent_scope"), "local")

    def test_generate_claude_command_includes_selected_scope(self) -> None:
        profile = {
            "profile_id": "p-claude",
            "name": "Claude Scope",
            "agent_type": "claude_code",
            "agent_scope": "user",
            "workspace": str(self.workspace),
            "agent_id": "claude-user-1",
        }
        upsert = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(upsert.get("ok"), msg=upsert)
        generated = agent_configs.generate_config(self.paths, "p-claude", save_to_file=False)
        self.assertTrue(generated.get("ok"), msg=generated)
        command_text = str((generated.get("generated") or {}).get("command_text", ""))
        self.assertIn("claude mcp add ai-runtime-guard", command_text)
        self.assertIn("--scope user", command_text)

    def test_generate_codex_command_respects_project_scope(self) -> None:
        profile = {
            "profile_id": "p-codex",
            "name": "Codex Scope",
            "agent_type": "codex",
            "agent_scope": "project",
            "workspace": str(self.workspace),
            "agent_id": "codex-project-1",
        }
        upsert = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(upsert.get("ok"), msg=upsert)
        generated = agent_configs.generate_config(self.paths, "p-codex", save_to_file=False)
        self.assertTrue(generated.get("ok"), msg=generated)
        command_text = str((generated.get("generated") or {}).get("command_text", ""))
        self.assertIn("codex mcp add ai-runtime-guard", command_text)
        self.assertIn("--scope project", command_text)
        self.assertIn("AIRG_AGENT_ID=codex-project-1", command_text)


if __name__ == "__main__":
    unittest.main()
