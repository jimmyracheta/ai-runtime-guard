import json
import hashlib
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import agent_posture


class AgentPostureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.home = self.base / "home"
        self.home.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def _mcp_payload() -> dict:
        return {
            "mcpServers": {
                "ai-runtime-guard": {
                    "command": "/tmp/airg-server",
                    "args": [],
                }
            }
        }

    def test_claude_posture_detects_project_local_user_managed_scopes(self) -> None:
        (self.workspace / ".mcp.json").write_text(json.dumps(self._mcp_payload(), indent=2))
        (self.home / ".claude.json").write_text(
            json.dumps(
                {
                    "mcpServers": self._mcp_payload()["mcpServers"],
                    "projects": {
                        str(self.workspace): self._mcp_payload(),
                    },
                },
                indent=2,
            )
        )
        managed_path = self.base / "managed-mcp.json"
        managed_path.write_text(json.dumps(self._mcp_payload(), indent=2))

        profile = {
            "profile_id": "p1",
            "name": "Claude Code 1",
            "agent_type": "claude_code",
            "agent_id": "claude-code-1",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home), patch(
            "agent_posture._claude_managed_paths",
            return_value=[managed_path],
        ):
            row = agent_posture.build_posture_for_profile(profile)

        scopes = set(row.get("mcp_detected_scopes", []))
        self.assertEqual(scopes, {"project", "local", "user", "managed"})
        self.assertTrue(row.get("signals", {}).get("airg_mcp_present"))

    def test_claude_posture_detects_local_scope_only(self) -> None:
        (self.home / ".claude.json").write_text(
            json.dumps(
                {
                    "projects": {
                        str(self.workspace): self._mcp_payload(),
                    }
                },
                indent=2,
            )
        )
        profile = {
            "profile_id": "p2",
            "name": "Claude Local",
            "agent_type": "claude_code",
            "agent_id": "claude-local",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home), patch(
            "agent_posture._claude_managed_paths",
            return_value=[],
        ):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertIn("local", row.get("mcp_detected_scopes", []))
        self.assertTrue(row.get("signals", {}).get("airg_mcp_present"))

    def test_claude_posture_missing_mcp_files_is_safe(self) -> None:
        profile = {
            "profile_id": "p3",
            "name": "Claude Missing",
            "agent_type": "claude_code",
            "agent_id": "claude-missing",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home), patch(
            "agent_posture._claude_managed_paths",
            return_value=[],
        ):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "gray")
        self.assertFalse(row.get("signals", {}).get("airg_mcp_present"))
        self.assertEqual(row.get("mcp_detected_scopes", []), [])

    def test_claude_desktop_posture_detects_desktop_config(self) -> None:
        profile = {
            "profile_id": "p4",
            "name": "Claude Desktop",
            "agent_type": "claude_desktop",
            "agent_id": "claude-desktop-1",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            desktop_cfg = agent_posture._claude_desktop_config_path()
            desktop_cfg.parent.mkdir(parents=True, exist_ok=True)
            desktop_cfg.write_text(json.dumps(self._mcp_payload(), indent=2))
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "green")
        self.assertTrue(row.get("signals", {}).get("airg_mcp_present"))
        self.assertEqual(row.get("mcp_detected_scopes", []), ["desktop"])

    def test_claude_desktop_posture_missing_config_is_gray(self) -> None:
        profile = {
            "profile_id": "p5",
            "name": "Claude Desktop Missing",
            "agent_type": "claude_desktop",
            "agent_id": "claude-desktop-1",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "gray")
        self.assertFalse(row.get("signals", {}).get("airg_mcp_present"))
        self.assertEqual(row.get("mcp_detected_scopes", []), [])

    def test_detect_unregistered_excludes_registered_claude_desktop_config(self) -> None:
        profiles = [
            {
                "profile_id": "p5b",
                "name": "Claude Desktop",
                "agent_type": "claude_desktop",
                "agent_id": "claude-desktop-1",
                "workspace": str(self.workspace),
            }
        ]

        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            desktop_cfg = agent_posture._claude_desktop_config_path()
            desktop_cfg.parent.mkdir(parents=True, exist_ok=True)
            desktop_cfg.write_text(json.dumps(self._mcp_payload(), indent=2))
            discovered = agent_posture.detect_unregistered_for_profiles(profiles)

        self.assertEqual(discovered, [])

    def test_codex_posture_detects_global_scope(self) -> None:
        codex_cfg = self.home / ".codex" / "config.toml"
        codex_cfg.parent.mkdir(parents=True, exist_ok=True)
        codex_cfg.write_text(
            '[mcp_servers.ai-runtime-guard]\n'
            'command = "/tmp/airg-server"\n'
            'args = []\n'
            '\n'
            '[mcp_servers.ai-runtime-guard.env]\n'
            'AIRG_AGENT_ID = "codex-1"\n'
            f'AIRG_WORKSPACE = "{self.workspace}"\n'
        )
        profile = {
            "profile_id": "p6",
            "name": "Codex Global",
            "agent_type": "codex",
            "agent_scope": "global",
            "agent_id": "codex-1",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "red")
        self.assertTrue(row.get("signals", {}).get("airg_mcp_present"))
        self.assertIn("global", row.get("mcp_detected_scopes", []))

    def test_codex_posture_detects_project_scope(self) -> None:
        codex_cfg = self.workspace / ".codex" / "config.toml"
        codex_cfg.parent.mkdir(parents=True, exist_ok=True)
        codex_cfg.write_text(
            '[mcp_servers.ai-runtime-guard]\n'
            'command = "/tmp/airg-server"\n'
            'args = []\n'
            '\n'
            '[mcp_servers.ai-runtime-guard.env]\n'
            'AIRG_AGENT_ID = "codex-1"\n'
            f'AIRG_WORKSPACE = "{self.workspace}"\n'
        )
        profile = {
            "profile_id": "p7",
            "name": "Codex Project",
            "agent_type": "codex",
            "agent_scope": "project",
            "agent_id": "codex-1",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "red")
        self.assertTrue(row.get("signals", {}).get("airg_mcp_present"))
        self.assertIn("project", row.get("mcp_detected_scopes", []))

    def test_cursor_posture_detects_project_and_global_scopes(self) -> None:
        project_cfg = self.workspace / ".cursor" / "mcp.json"
        project_cfg.parent.mkdir(parents=True, exist_ok=True)
        project_cfg.write_text(json.dumps(self._mcp_payload(), indent=2))

        global_cfg = self.home / ".cursor" / "mcp.json"
        global_cfg.parent.mkdir(parents=True, exist_ok=True)
        global_cfg.write_text(json.dumps(self._mcp_payload(), indent=2))

        profile = {
            "profile_id": "p-cursor",
            "name": "Cursor",
            "agent_type": "cursor",
            "agent_scope": "project",
            "agent_id": "cursor-1",
            "workspace": str(self.workspace),
        }

        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "red")
        self.assertTrue(row.get("signals", {}).get("airg_mcp_present"))
        self.assertEqual(set(row.get("mcp_detected_scopes", [])), {"project", "global"})
        self.assertTrue(bool(row.get("mcp_scope_match")))

    def test_cursor_posture_yellow_when_hook_enforcement_present(self) -> None:
        project_cfg = self.workspace / ".cursor" / "mcp.json"
        project_cfg.parent.mkdir(parents=True, exist_ok=True)
        project_cfg.write_text(json.dumps(self._mcp_payload(), indent=2))
        hooks_path = self.workspace / ".cursor" / "hooks.json"
        hooks_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "preToolUse": [
                            {"command": "/usr/local/bin/airg-hook", "matcher": "Shell", "airg_managed": True},
                            {"command": "/usr/local/bin/airg-hook", "matcher": "Write", "airg_managed": True},
                            {"command": "/usr/local/bin/airg-hook", "matcher": "Delete", "airg_managed": True},
                        ],
                        "beforeShellExecution": [{"command": "/usr/local/bin/airg-hook", "airg_managed": True}],
                        "beforeMCPExecution": [{"command": "/usr/local/bin/airg-hook", "airg_managed": True}],
                    },
                },
                indent=2,
            )
        )
        profile = {
            "profile_id": "p-cursor-y",
            "name": "Cursor",
            "agent_type": "cursor",
            "agent_scope": "project",
            "agent_id": "cursor-1",
            "workspace": str(self.workspace),
        }
        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            row = agent_posture.build_posture_for_profile(profile)
        self.assertEqual(row.get("status"), "yellow")
        self.assertTrue(bool(row.get("signals", {}).get("hook_enforcement_active")))
        self.assertFalse(bool(row.get("signals", {}).get("sandbox_hardened")))

    def test_cursor_posture_green_when_hooks_fail_closed_and_sandbox_hardened(self) -> None:
        project_cfg = self.workspace / ".cursor" / "mcp.json"
        project_cfg.parent.mkdir(parents=True, exist_ok=True)
        project_cfg.write_text(json.dumps(self._mcp_payload(), indent=2))
        hooks_path = self.workspace / ".cursor" / "hooks.json"
        hooks_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "preToolUse": [
                            {"command": "/usr/local/bin/airg-hook", "matcher": "Shell", "airg_managed": True},
                            {"command": "/usr/local/bin/airg-hook", "matcher": "Write", "airg_managed": True},
                            {"command": "/usr/local/bin/airg-hook", "matcher": "Delete", "airg_managed": True},
                        ],
                        "beforeShellExecution": [{"command": "/usr/local/bin/airg-hook", "airg_managed": True, "failClosed": True}],
                        "beforeMCPExecution": [{"command": "/usr/local/bin/airg-hook", "airg_managed": True, "failClosed": True}],
                    },
                },
                indent=2,
            )
        )
        sandbox_path = self.workspace / ".cursor" / "sandbox.json"
        sandbox_path.write_text(
            json.dumps(
                {
                    "type": "workspace_readwrite",
                    "disableTmpWrite": True,
                    "networkPolicy": {"default": "deny", "allow": [], "deny": []},
                },
                indent=2,
            )
        )
        profile = {
            "profile_id": "p-cursor-g",
            "name": "Cursor",
            "agent_type": "cursor",
            "agent_scope": "project",
            "agent_id": "cursor-1",
            "workspace": str(self.workspace),
        }
        with patch("agent_posture.pathlib.Path.home", return_value=self.home):
            row = agent_posture.build_posture_for_profile(profile)
        self.assertEqual(row.get("status"), "green")
        self.assertTrue(bool(row.get("signals", {}).get("hook_enforcement_active")))
        self.assertTrue(bool(row.get("signals", {}).get("hook_fail_closed_active")))
        self.assertTrue(bool(row.get("signals", {}).get("sandbox_hardened")))

    def test_codex_posture_green_when_all_tiers_present_and_in_sync(self) -> None:
        codex_cfg = self.home / ".codex" / "config.toml"
        codex_cfg.parent.mkdir(parents=True, exist_ok=True)
        codex_cfg.write_text(
            'sandbox_mode = "read-only"\n'
            'approval_policy = "untrusted"\n'
            '\n'
            '[sandbox_workspace_write]\n'
            'network_access = false\n'
            'exclude_slash_tmp = true\n'
            'exclude_tmpdir_env_var = true\n'
            'writable_roots = []\n'
            '\n'
            '[mcp_servers.ai-runtime-guard]\n'
            'command = "/tmp/airg-server"\n'
            'args = []\n'
            '\n'
            '[mcp_servers.ai-runtime-guard.env]\n'
            'AIRG_AGENT_ID = "codex-1"\n'
            f'AIRG_WORKSPACE = "{self.workspace}"\n'
        )
        agents_doc = self.home / ".codex" / "AGENTS.md"
        agents_doc.parent.mkdir(parents=True, exist_ok=True)
        agents_doc.write_text(
            "<!-- AIRG_CODEX_TIER1_BEGIN -->\nTier1\n<!-- AIRG_CODEX_TIER1_END -->\n"
        )
        policy_path = self.base / "policy.json"
        policy = {
            "blocked": {"commands": ["rm -rf"], "paths": [], "extensions": []},
            "requires_confirmation": {"commands": [], "paths": []},
            "allowed": {"paths_whitelist": []},
            "agent_overrides": {},
        }
        policy_path.write_text(json.dumps(policy))
        policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        rules_body = (
            'prefix_rule(pattern=["rm", "-rf"], decision="forbidden", '
            'justification="Blocked by AIRG policy. Use mcp__ai-runtime-guard__execute_command instead.")\n'
        )
        rules_hash = hashlib.sha256(rules_body.encode("utf-8")).hexdigest()
        rules_file = self.home / ".codex" / "rules" / "airg.rules"
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        rules_file.write_text(
            '# AIRG_CODEX_TIER2_BEGIN {"agent_id":"codex-1","policy_hash":"'
            + policy_hash
            + '","mirror_approvals_mode":"allow","include_requires_confirmation":false,"generated_rules_hash":"'
            + rules_hash
            + '"}\n'
            + rules_body
            + "# AIRG_CODEX_TIER2_END\n"
        )

        profile = {
            "profile_id": "p8",
            "name": "Codex Hardened",
            "agent_type": "codex",
            "agent_scope": "global",
            "agent_id": "codex-1",
            "workspace": str(self.workspace),
        }
        with patch("agent_posture.pathlib.Path.home", return_value=self.home), patch.dict(
            "os.environ",
            {"AIRG_POLICY_PATH": str(policy_path)},
            clear=False,
        ):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "green")
        self.assertTrue(row.get("signals", {}).get("tier1_guidance_present"))
        self.assertTrue(row.get("signals", {}).get("tier2_rules_present"))
        self.assertTrue(row.get("signals", {}).get("tier2_rules_in_sync"))
        self.assertTrue(row.get("signals", {}).get("tier2_mirror_approvals_configured"))
        self.assertTrue(row.get("signals", {}).get("sandbox_mode_maximum"))
        self.assertTrue(row.get("signals", {}).get("approval_policy_maximum"))

    def test_codex_project_posture_reads_project_scope_artifacts(self) -> None:
        codex_cfg = self.workspace / ".codex" / "config.toml"
        codex_cfg.parent.mkdir(parents=True, exist_ok=True)
        codex_cfg.write_text(
            'sandbox_mode = "read-only"\n'
            'approval_policy = "untrusted"\n'
            '\n'
            '[sandbox_workspace_write]\n'
            'network_access = false\n'
            'exclude_slash_tmp = true\n'
            'exclude_tmpdir_env_var = true\n'
            'writable_roots = []\n'
            '\n'
            '[mcp_servers.ai-runtime-guard]\n'
            'command = "/tmp/airg-server"\n'
            'args = []\n'
            '\n'
            '[mcp_servers.ai-runtime-guard.env]\n'
            'AIRG_AGENT_ID = "codex-project-1"\n'
            f'AIRG_WORKSPACE = "{self.workspace}"\n'
        )
        agents_doc = self.workspace / ".codex" / "AGENTS.md"
        agents_doc.write_text(
            "<!-- AIRG_CODEX_TIER1_BEGIN -->\nTier1\n<!-- AIRG_CODEX_TIER1_END -->\n"
        )
        policy_path = self.base / "policy-project.json"
        policy = {
            "blocked": {"commands": ["rm -rf"], "paths": [], "extensions": []},
            "requires_confirmation": {"commands": [], "paths": []},
            "allowed": {"paths_whitelist": []},
            "agent_overrides": {},
        }
        policy_path.write_text(json.dumps(policy))
        policy_hash = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        rules_body = (
            'prefix_rule(pattern=["rm", "-rf"], decision="forbidden", '
            'justification="Blocked by AIRG policy. Use mcp__ai-runtime-guard__execute_command instead.")\n'
        )
        rules_hash = hashlib.sha256(rules_body.encode("utf-8")).hexdigest()
        rules_file = self.workspace / ".codex" / "rules" / "airg.rules"
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        rules_file.write_text(
            '# AIRG_CODEX_TIER2_BEGIN {"agent_id":"codex-project-1","policy_hash":"'
            + policy_hash
            + '","mirror_approvals_mode":"allow","include_requires_confirmation":false,"generated_rules_hash":"'
            + rules_hash
            + '"}\n'
            + rules_body
            + "# AIRG_CODEX_TIER2_END\n"
        )

        profile = {
            "profile_id": "p9",
            "name": "Codex Project Hardened",
            "agent_type": "codex",
            "agent_scope": "project",
            "agent_id": "codex-project-1",
            "workspace": str(self.workspace),
        }
        with patch("agent_posture.pathlib.Path.home", return_value=self.home), patch.dict(
            "os.environ",
            {"AIRG_POLICY_PATH": str(policy_path)},
            clear=False,
        ):
            row = agent_posture.build_posture_for_profile(profile)

        self.assertEqual(row.get("status"), "green")
        self.assertEqual(row.get("signal_scopes", {}).get("tier1_guidance_present"), ["project"])
        self.assertEqual(row.get("signal_scopes", {}).get("tier2_rules_present"), ["project"])


if __name__ == "__main__":
    unittest.main()
