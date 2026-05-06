import json
import pathlib
import re
import shutil
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
        # Undo All restores hardening changes only; MCP config remains in place.
        self.assertTrue(workspace_mcp.exists())

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

    def test_cursor_apply_global_scope_writes_home_cursor_config(self) -> None:
        profile = {
            "profile_id": "p-cursor-global",
            "agent_type": "cursor",
            "agent_scope": "global",
            "workspace": str(self.workspace),
            "agent_id": "cursor-global",
        }
        home_dir = self.base / "home"
        home_dir.mkdir(parents=True, exist_ok=True)
        target = home_dir / ".cursor" / "mcp.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"mcpServers": {"existing": {"command": "node"}}}, indent=2))

        with patch("agent_configurator.pathlib.Path.home", return_value=home_dir):
            applied = agent_configurator.apply_hardening(self.paths, profile)
        self.assertTrue(applied.get("ok"), msg=applied)
        merged = json.loads(target.read_text())
        self.assertIn("existing", merged.get("mcpServers", {}))
        self.assertIn("ai-runtime-guard", merged.get("mcpServers", {}))
        permissions = home_dir / ".cursor" / "permissions.json"
        self.assertTrue(permissions.exists())
        permissions_payload = json.loads(permissions.read_text())
        self.assertEqual(permissions_payload.get("mcpAllowlist"), ["ai-runtime-guard:*"])
        self.assertEqual(permissions_payload.get("terminalAllowlist"), [])

    def test_cursor_apply_project_scope_writes_hooks_sandbox_and_cursorignore(self) -> None:
        profile = {
            "profile_id": "p-cursor-hardening",
            "agent_type": "cursor",
            "agent_scope": "project",
            "workspace": str(self.workspace),
            "agent_id": "cursor-hardening",
        }
        self.paths["policy_path"].write_text(
            json.dumps(
                {
                    "blocked": {"commands": [], "paths": [".env", "secrets.json"], "extensions": [".pem"]},
                    "requires_confirmation": {"commands": [], "paths": []},
                    "allowed": {"paths_whitelist": []},
                    "network": {"allowed_domains": ["pypi.org"], "blocked_domains": ["example.com"]},
                }
            )
        )
        cursor_mcp = self.workspace / ".cursor" / "mcp.json"
        cursor_mcp.parent.mkdir(parents=True, exist_ok=True)
        cursor_mcp.write_text(json.dumps({"mcpServers": {}}, indent=2))
        options = {
            "strict_enforcement": True,
            "advanced_enforcement": True,
            "fail_closed": True,
            "permissions_enabled": True,
            "sandbox_enabled": True,
            "sandbox_type": "workspace_readwrite",
            "sandbox_disable_tmp_write": True,
            "sandbox_sync_network_from_policy": True,
            "cursorignore_sync": True,
        }

        applied = agent_configurator.apply_hardening(self.paths, profile, options=options)
        self.assertTrue(applied.get("ok"), msg=applied)

        hooks_file = self.workspace / ".cursor" / "hooks.json"
        self.assertTrue(hooks_file.exists())
        hooks_payload = json.loads(hooks_file.read_text())
        pretool = hooks_payload.get("hooks", {}).get("preToolUse", [])
        matchers = {str(item.get("matcher", "")) for item in pretool if isinstance(item, dict)}
        self.assertTrue({"Shell", "Write", "Delete", "Read", "Grep"}.issubset(matchers))
        before_shell = hooks_payload.get("hooks", {}).get("beforeShellExecution", [])
        self.assertTrue(any(bool(item.get("failClosed", False)) for item in before_shell if isinstance(item, dict)))
        before_mcp = hooks_payload.get("hooks", {}).get("beforeMCPExecution", [])
        self.assertTrue(any(bool(item.get("failClosed", False)) for item in before_mcp if isinstance(item, dict)))

        sandbox_file = self.workspace / ".cursor" / "sandbox.json"
        self.assertTrue(sandbox_file.exists())
        sandbox_payload = json.loads(sandbox_file.read_text())
        self.assertEqual(sandbox_payload.get("type"), "workspace_readwrite")
        self.assertTrue(bool(sandbox_payload.get("disableTmpWrite", False)))
        self.assertEqual(sandbox_payload.get("networkPolicy", {}).get("default"), "deny")
        self.assertIn("pypi.org", sandbox_payload.get("networkPolicy", {}).get("allow", []))
        self.assertIn("example.com", sandbox_payload.get("networkPolicy", {}).get("deny", []))

        cursorignore_file = self.workspace / ".cursorignore"
        self.assertTrue(cursorignore_file.exists())
        cursorignore_text = cursorignore_file.read_text()
        self.assertIn("AIRG_CURSORIGNORE_BEGIN", cursorignore_text)
        self.assertIn("**/.env", cursorignore_text)
        self.assertIn("**/secrets.json", cursorignore_text)
        self.assertIn("**/*.pem", cursorignore_text)

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

    def test_codex_apply_writes_tiers_and_undo_preserves_mcp(self) -> None:
        profile = {
            "profile_id": "p-codex-hardening",
            "agent_type": "codex",
            "agent_scope": "global",
            "workspace": str(self.workspace),
            "agent_id": "codex-1",
        }
        options = {
            "tier1_guidance": True,
            "tier2_mirror": True,
            "tier2_mirror_approvals_mode": "allow",
            "tier3_sandbox_mode": "workspace-write",
            "tier3_approval_policy": "on-request",
            "tier3_workspace_write_network_access": False,
            "tier3_workspace_write_exclude_slash_tmp": True,
            "tier3_workspace_write_exclude_tmpdir_env_var": True,
            "tier3_workspace_write_writable_roots": [],
        }
        self.paths["policy_path"].write_text(
            json.dumps(
                {
                    "blocked": {"commands": ["rm -rf"], "paths": [], "extensions": []},
                    "requires_confirmation": {"commands": [], "paths": []},
                    "allowed": {"paths_whitelist": []},
                    "agent_overrides": {},
                }
            )
        )
        home_dir = self.base / "home"
        home_dir.mkdir(parents=True, exist_ok=True)
        codex_cfg = home_dir / ".codex" / "config.toml"
        codex_cfg.parent.mkdir(parents=True, exist_ok=True)
        codex_cfg.write_text('model = "gpt-5"\n')

        with patch("agent_configurator.pathlib.Path.home", return_value=home_dir), patch(
            "agent_configurator.shutil.which",
            side_effect=lambda name: None if name == "codex" else shutil.which(name),
        ):
            applied = agent_configurator.apply_hardening(self.paths, profile, options=options, auto_add_mcp=True)
            self.assertTrue(applied.get("ok"), msg=applied)
            self.assertTrue(agent_configurator.undo_available(self.paths, "p-codex-hardening"))

            agents_doc = home_dir / ".codex" / "AGENTS.md"
            self.assertTrue(agents_doc.exists())
            agents_text = agents_doc.read_text()
            self.assertIn("AIRG_CODEX_TIER1_BEGIN", agents_text)
            self.assertIn("mcp__ai-runtime-guard__execute_command", agents_text)

            rules_file = home_dir / ".codex" / "rules" / "airg.rules"
            self.assertTrue(rules_file.exists())
            rules_text = rules_file.read_text()
            self.assertIn("AIRG_CODEX_TIER2_BEGIN", rules_text)
            self.assertIn("prefix_rule(", rules_text)

            cfg_text = codex_cfg.read_text()
            self.assertIn('[mcp_servers.ai-runtime-guard]', cfg_text)
            self.assertIn('sandbox_mode = "workspace-write"', cfg_text)
            self.assertIn('approval_policy = "on-request"', cfg_text)
            self.assertIn('exclude_slash_tmp = true', cfg_text)
            self.assertIn('exclude_tmpdir_env_var = true', cfg_text)

            undone = agent_configurator.undo_hardening(self.paths, profile)
            self.assertTrue(undone.get("ok"), msg=undone)
            # Undo all should keep MCP config in place and only revert hardening overlays.
            undone_cfg_text = codex_cfg.read_text()
            self.assertIn('[mcp_servers.ai-runtime-guard]', undone_cfg_text)
            self.assertNotIn('sandbox_mode = "workspace-write"', undone_cfg_text)

    def test_codex_project_scope_writes_project_artifacts(self) -> None:
        profile = {
            "profile_id": "p-codex-project-hardening",
            "agent_type": "codex",
            "agent_scope": "project",
            "workspace": str(self.workspace),
            "agent_id": "codex-project-1",
        }
        options = {
            "tier1_guidance": True,
            "tier2_mirror": True,
            "tier2_mirror_approvals_mode": "approve",
            "tier3_sandbox_mode": "workspace-write",
            "tier3_approval_policy": "on-request",
            "tier3_workspace_write_network_access": False,
            "tier3_workspace_write_exclude_slash_tmp": True,
            "tier3_workspace_write_exclude_tmpdir_env_var": True,
            "tier3_workspace_write_writable_roots": [],
        }
        self.paths["policy_path"].write_text(
            json.dumps(
                {
                    "blocked": {"commands": ["rm -rf"], "paths": [], "extensions": []},
                    "requires_confirmation": {"commands": ["git push"], "paths": []},
                    "allowed": {"paths_whitelist": []},
                    "agent_overrides": {},
                }
            )
        )
        home_dir = self.base / "home"
        home_dir.mkdir(parents=True, exist_ok=True)

        with patch("agent_configurator.pathlib.Path.home", return_value=home_dir), patch(
            "agent_configurator.shutil.which",
            side_effect=lambda name: None if name == "codex" else shutil.which(name),
        ):
            applied = agent_configurator.apply_hardening(self.paths, profile, options=options, auto_add_mcp=True)
        self.assertTrue(applied.get("ok"), msg=applied)

        project_codex_dir = self.workspace / ".codex"
        self.assertTrue((project_codex_dir / "AGENTS.md").exists())
        self.assertTrue((project_codex_dir / "rules" / "airg.rules").exists())
        self.assertTrue((project_codex_dir / "config.toml").exists())
        self.assertIn('[mcp_servers.ai-runtime-guard]', (project_codex_dir / "config.toml").read_text())
        self.assertFalse((home_dir / ".codex" / "AGENTS.md").exists())

    def test_codex_project_scope_hardening_is_idempotent(self) -> None:
        profile = {
            "profile_id": "p-codex-project-idempotent",
            "agent_type": "codex",
            "agent_scope": "project",
            "workspace": str(self.workspace),
            "agent_id": "codex-project-idempotent",
        }
        codex_root = self.workspace / ".codex"
        codex_root.mkdir(parents=True, exist_ok=True)
        (codex_root / "AGENTS.md").write_text("Intro line\n\n")
        (codex_root / "config.toml").write_text('model = "gpt-5"\n\n')
        (codex_root / "rules").mkdir(parents=True, exist_ok=True)
        (codex_root / "rules" / "airg.rules").write_text("# existing heading\n\n")

        home_dir = self.base / "home"
        home_dir.mkdir(parents=True, exist_ok=True)

        with patch("agent_configurator.pathlib.Path.home", return_value=home_dir), patch(
            "agent_configurator.shutil.which",
            side_effect=lambda name: None if name == "codex" else shutil.which(name),
        ):
            first = agent_configurator.apply_hardening(self.paths, profile, auto_add_mcp=True)
        self.assertTrue(first.get("ok"), msg=first)

        agents_once = (codex_root / "AGENTS.md").read_text()
        config_once = (codex_root / "config.toml").read_text()
        rules_once = (codex_root / "rules" / "airg.rules").read_text()

        with patch("agent_configurator.pathlib.Path.home", return_value=home_dir), patch(
            "agent_configurator.shutil.which",
            side_effect=lambda name: None if name == "codex" else shutil.which(name),
        ):
            second = agent_configurator.apply_hardening(self.paths, profile, auto_add_mcp=True)
        self.assertTrue(second.get("ok"), msg=second)

        self.assertEqual((codex_root / "AGENTS.md").read_text(), agents_once)
        self.assertEqual((codex_root / "config.toml").read_text(), config_once)
        rules_twice = (codex_root / "rules" / "airg.rules").read_text()
        self.assertEqual(rules_twice.count("AIRG_CODEX_TIER2_BEGIN"), 1)
        self.assertEqual(rules_twice.count("AIRG_CODEX_TIER2_END"), 1)
        normalize_generated_at = lambda text: re.sub(
            r'"generated_at":\s*"[^"]+"',
            '"generated_at":"<normalized>"',
            text,
        )
        self.assertEqual(normalize_generated_at(rules_twice), normalize_generated_at(rules_once))


if __name__ == "__main__":
    unittest.main()
