"""
Tests for the bridged (in-sandbox shim) MCP config generation — W1.

Topology A bridge wiring: when ``bridged=True`` is requested, the generated
MCP server config should:
  - point ``command`` at the current Python interpreter (not airg_cli server)
  - point ``args`` at ``scripts/airg_stdio_bridge.py``
  - include ``AIRG_SOCKET_PATH`` in env, set to the per-agent socket path
    (same convention as ``airg_cli._agent_socket_path``)
  - still include ``AIRG_AGENT_ID`` and ``AIRG_WORKSPACE``

When ``bridged=False`` (the default), the output MUST be UNCHANGED from the
pre-existing direct-stdio AIRG spawn (regression guard).

The path convention must match ``airg_cli._agent_socket_path`` exactly:
  ``$state_dir/sockets/<safe_agent_id>.sock``

Also exercises ``mcp_config_manager.plan_apply`` with ``bridged=True`` for the
Codex project scope (the documented first target for the bridged path).

See: docs/os-enforcement/transport-bridge-design.md §4.2, §8.
"""

import pathlib
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

import agent_configs
import mcp_config_manager


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------


def _make_paths(base: pathlib.Path) -> dict:
    workspace = base / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    paths = {
        "policy_path": base / "policy.json",
        "approval_db_path": base / "state" / "approvals.db",
        "approval_hmac_key_path": base / "state" / "approvals.db.hmac.key",
        "log_path": base / "state" / "activity.log",
        "reports_db_path": base / "state" / "reports.db",
    }
    paths["approval_db_path"].parent.mkdir(parents=True, exist_ok=True)
    paths["policy_path"].write_text("{}\n")
    paths["approval_hmac_key_path"].write_text("hmac\n")
    paths["log_path"].write_text("\n")
    paths["reports_db_path"].write_text("\n")
    return paths, workspace


def _state_dir_from_paths(paths: dict) -> pathlib.Path:
    return paths["approval_db_path"].expanduser().resolve().parent


def _expected_socket_path(state_dir: pathlib.Path, agent_id: str) -> pathlib.Path:
    """Replicate the airg_cli._agent_socket_path formula for verification.

    ``$state_dir/sockets/<safe_agent_id>.sock``
    (same regex as airg_cli: ``[^A-Za-z0-9_.-]`` → ``_``)
    """
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", agent_id or "default")
    return (state_dir / "sockets" / f"{safe_id}.sock").resolve()


# ---------------------------------------------------------------------------
# Test 1 — agent_configs.generate_config default is UNCHANGED
# ---------------------------------------------------------------------------


class TestBridgedMCPConfigDefaultUnchanged(unittest.TestCase):
    """Regression guard: default (bridged=False) output must be identical to
    pre-existing direct-stdio AIRG spawn."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.paths, self.workspace = _make_paths(self.base)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _upsert(self, agent_type: str, agent_id: str, scope: str = "project") -> dict:
        profile = {
            "profile_id": f"p-{agent_type}-{agent_id}",
            "name": f"{agent_type} test",
            "agent_type": agent_type,
            "agent_scope": scope,
            "workspace": str(self.workspace),
            "agent_id": agent_id,
        }
        result = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(result.get("ok"), msg=result)
        return result["profile"]

    def _assert_direct_stdio_block(self, block: dict, agent_id: str) -> None:
        """Assert the block points at AIRG directly (not the shim)."""
        self.assertEqual(block.get("command"), str(pathlib.Path(sys.executable).resolve()))
        self.assertEqual(block.get("args"), ["-m", "airg_cli", "server"])
        env = block.get("env", {})
        self.assertEqual(env.get("AIRG_AGENT_ID"), agent_id)
        self.assertIn("AIRG_WORKSPACE", env)
        self.assertNotIn("AIRG_SOCKET_PATH", env)

    def test_codex_default_is_direct_stdio(self) -> None:
        """generate_config(bridged=False) for codex produces direct-stdio spawn."""
        self._upsert("codex", "codex-direct-1", scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, "p-codex-codex-direct-1", save_to_file=False
            )
        self.assertTrue(result.get("ok"), msg=result)
        gen = result["generated"]
        self.assertFalse(gen.get("bridged"), "default should have bridged=False")
        block = gen["command_json"]
        self._assert_direct_stdio_block(block, "codex-direct-1")

    def test_claude_code_default_is_direct_stdio(self) -> None:
        """generate_config(bridged=False) for claude_code produces direct-stdio spawn."""
        self._upsert("claude_code", "cc-direct-1", scope="project")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, "p-claude_code-cc-direct-1", save_to_file=False
            )
        self.assertTrue(result.get("ok"), msg=result)
        gen = result["generated"]
        self.assertFalse(gen.get("bridged"))
        block = gen["command_json"]
        self._assert_direct_stdio_block(block, "cc-direct-1")

    def test_cursor_default_is_direct_stdio(self) -> None:
        """generate_config(bridged=False) for cursor produces direct-stdio spawn."""
        self._upsert("cursor", "cursor-direct-1", scope="project")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, "p-cursor-cursor-direct-1", save_to_file=False
            )
        self.assertTrue(result.get("ok"), msg=result)
        gen = result["generated"]
        self.assertFalse(gen.get("bridged"))
        block = gen["command_json"]
        self._assert_direct_stdio_block(block, "cursor-direct-1")


# ---------------------------------------------------------------------------
# Test 2 — agent_configs.generate_config bridged=True
# ---------------------------------------------------------------------------


class TestBridgedMCPConfigBridgedMode(unittest.TestCase):
    """Bridged (bridged=True) output must point at the shim with AIRG_SOCKET_PATH."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.paths, self.workspace = _make_paths(self.base)
        self.state_dir = _state_dir_from_paths(self.paths)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _upsert(self, agent_type: str, agent_id: str, scope: str = "project") -> dict:
        profile = {
            "profile_id": f"p-{agent_type}-{agent_id}",
            "name": f"{agent_type} bridged test",
            "agent_type": agent_type,
            "agent_scope": scope,
            "workspace": str(self.workspace),
            "agent_id": agent_id,
        }
        result = agent_configs.upsert_profile(self.paths, profile)
        self.assertTrue(result.get("ok"), msg=result)
        return result["profile"]

    def _assert_bridged_block(self, block: dict, agent_id: str) -> None:
        """Assert the block points at the shim with correct env."""
        # command: current interpreter
        self.assertEqual(
            block.get("command"),
            str(pathlib.Path(sys.executable).resolve()),
            "bridged command must be the current Python interpreter",
        )
        # args: [path to airg_stdio_bridge.py] — only one element, no -m flag
        args = block.get("args", [])
        self.assertEqual(len(args), 1, f"bridged args should be [shim_path], got {args}")
        shim_arg = args[0]
        self.assertTrue(
            shim_arg.endswith("airg_stdio_bridge.py"),
            f"bridged arg must point at airg_stdio_bridge.py, got {shim_arg!r}",
        )
        # Must not be the -m airg_cli server invocation
        self.assertNotEqual(args, ["-m", "airg_cli", "server"])

        # env: AIRG_SOCKET_PATH must be set
        env = block.get("env", {})
        self.assertIn("AIRG_SOCKET_PATH", env, "bridged env must include AIRG_SOCKET_PATH")
        self.assertIn("AIRG_AGENT_ID", env)
        self.assertEqual(env.get("AIRG_AGENT_ID"), agent_id)
        self.assertIn("AIRG_WORKSPACE", env)

    def _assert_socket_path_convention(self, socket_path: str, agent_id: str) -> None:
        """Assert the socket path matches airg_cli._agent_socket_path convention."""
        expected = _expected_socket_path(self.state_dir, agent_id)
        actual = pathlib.Path(socket_path)
        # The actual path must resolve to the same file (allowing /private/tmp symlinks)
        self.assertEqual(
            actual.resolve(),
            expected.resolve(),
            f"AIRG_SOCKET_PATH {socket_path!r} != expected {expected!r}",
        )

    def test_codex_bridged_command_points_at_shim(self) -> None:
        """generate_config(bridged=True) for codex: command points at airg_stdio_bridge.py."""
        agent_id = "codex-bridge-1"
        self._upsert("codex", agent_id, scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        gen = result["generated"]
        self.assertTrue(gen.get("bridged"), "result should carry bridged=True flag")
        block = gen["command_json"]
        self._assert_bridged_block(block, agent_id)

    def test_codex_bridged_socket_path_matches_airg_cli_convention(self) -> None:
        """AIRG_SOCKET_PATH in bridged config matches _agent_socket_path convention."""
        agent_id = "codex-bridge-sockpath"
        self._upsert("codex", agent_id, scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        block = result["generated"]["command_json"]
        socket_path = block["env"]["AIRG_SOCKET_PATH"]
        self._assert_socket_path_convention(socket_path, agent_id)

    def test_codex_bridged_agent_identity_env_preserved(self) -> None:
        """AIRG_AGENT_ID and AIRG_WORKSPACE are preserved in bridged env."""
        agent_id = "codex-bridge-identity"
        self._upsert("codex", agent_id, scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        env = result["generated"]["command_json"]["env"]
        self.assertEqual(env["AIRG_AGENT_ID"], agent_id)
        self.assertEqual(env["AIRG_WORKSPACE"], str(self.workspace.resolve()))

    def test_claude_code_bridged_command_points_at_shim(self) -> None:
        """generate_config(bridged=True) for claude_code: command points at shim."""
        agent_id = "cc-bridge-1"
        self._upsert("claude_code", agent_id, scope="project")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-claude_code-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        block = result["generated"]["command_json"]
        self._assert_bridged_block(block, agent_id)
        socket_path = block["env"]["AIRG_SOCKET_PATH"]
        self._assert_socket_path_convention(socket_path, agent_id)

    def test_cursor_bridged_command_points_at_shim(self) -> None:
        """generate_config(bridged=True) for cursor: command points at shim."""
        agent_id = "cursor-bridge-1"
        self._upsert("cursor", agent_id, scope="project")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-cursor-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        block = result["generated"]["command_json"]
        self._assert_bridged_block(block, agent_id)
        socket_path = block["env"]["AIRG_SOCKET_PATH"]
        self._assert_socket_path_convention(socket_path, agent_id)

    def test_bridged_flag_false_is_default_and_produces_direct_spawn(self) -> None:
        """Explicit bridged=False produces the same output as the default (direct spawn)."""
        agent_id = "codex-explicit-false"
        self._upsert("codex", agent_id, scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result_default = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False
            )
            result_explicit_false = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False, bridged=False
            )
        for result in (result_default, result_explicit_false):
            self.assertTrue(result.get("ok"), msg=result)
            block = result["generated"]["command_json"]
            self.assertEqual(block["args"], ["-m", "airg_cli", "server"])
            self.assertNotIn("AIRG_SOCKET_PATH", block.get("env", {}))

    def test_bridged_shim_path_is_absolute(self) -> None:
        """The shim path in bridged args is absolute."""
        agent_id = "codex-shim-abs"
        self._upsert("codex", agent_id, scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        shim_arg = result["generated"]["command_json"]["args"][0]
        self.assertTrue(
            pathlib.Path(shim_arg).is_absolute(),
            f"shim path should be absolute, got {shim_arg!r}",
        )

    def test_bridged_agent_id_sanitization_matches_socket_convention(self) -> None:
        """Agent IDs with special characters are sanitized the same way in socket path."""
        # _agent_socket_path uses re.sub(r"[^A-Za-z0-9_.-]", "_", agent_id)
        # Test a valid agent_id (only safe chars per _AGENT_ID_PATTERN)
        agent_id = "codex-bridge.special_id"
        self._upsert("codex", agent_id, scope="global")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = agent_configs.generate_config(
                self.paths, f"p-codex-{agent_id}", save_to_file=False, bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        socket_path = result["generated"]["command_json"]["env"]["AIRG_SOCKET_PATH"]
        # Verify the socket filename matches the sanitized agent_id
        sock_name = pathlib.Path(socket_path).name
        expected_name = re.sub(r"[^A-Za-z0-9_.-]", "_", agent_id) + ".sock"
        self.assertEqual(sock_name, expected_name)


# ---------------------------------------------------------------------------
# Test 3 — mcp_config_manager.plan_apply bridged=True (Codex project scope)
# ---------------------------------------------------------------------------


class TestMCPConfigManagerBridgedPlan(unittest.TestCase):
    """mcp_config_manager.plan_apply with bridged=True uses the shim server_entry."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.paths, self.workspace = _make_paths(self.base)
        self.state_dir = _state_dir_from_paths(self.paths)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _codex_profile(self, scope: str = "global") -> dict:
        return {
            "profile_id": "p-codex-mgr",
            "name": "Codex bridged manager test",
            "agent_type": "codex",
            "agent_scope": scope,
            "workspace": str(self.workspace),
            "agent_id": "codex-mgr-bridge-1",
        }

    def test_plan_apply_default_uses_direct_block(self) -> None:
        """plan_apply without bridged uses the direct-stdio server_entry (regression)."""
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = mcp_config_manager.plan_apply(self.paths, self._codex_profile())
        self.assertTrue(result.get("ok"), msg=result)
        entry = result["plan"]["server_entry"]
        self.assertEqual(entry["args"], ["-m", "airg_cli", "server"])
        self.assertNotIn("AIRG_SOCKET_PATH", entry.get("env", {}))
        self.assertFalse(result["plan"].get("bridged"))

    def test_plan_apply_bridged_uses_shim_server_entry(self) -> None:
        """plan_apply(bridged=True) produces a shim-pointing server_entry."""
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = mcp_config_manager.plan_apply(
                self.paths, self._codex_profile(), bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        plan = result["plan"]
        self.assertTrue(plan.get("bridged"))
        entry = plan["server_entry"]

        # command: Python interpreter
        self.assertEqual(entry["command"], str(pathlib.Path(sys.executable).resolve()))
        # args: [shim path]
        self.assertEqual(len(entry["args"]), 1)
        self.assertTrue(entry["args"][0].endswith("airg_stdio_bridge.py"))
        # env: all three keys present
        env = entry["env"]
        self.assertIn("AIRG_SOCKET_PATH", env)
        self.assertIn("AIRG_AGENT_ID", env)
        self.assertIn("AIRG_WORKSPACE", env)

    def test_plan_apply_bridged_socket_path_matches_convention(self) -> None:
        """AIRG_SOCKET_PATH in plan_apply(bridged=True) matches airg_cli convention."""
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = mcp_config_manager.plan_apply(
                self.paths, self._codex_profile(), bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        socket_path = result["plan"]["server_entry"]["env"]["AIRG_SOCKET_PATH"]
        expected = _expected_socket_path(self.state_dir, "codex-mgr-bridge-1")
        self.assertEqual(
            pathlib.Path(socket_path).resolve(),
            expected.resolve(),
        )

    def test_plan_apply_bridged_codex_project_scope(self) -> None:
        """plan_apply(bridged=True) works for Codex project scope (first documented target)."""
        profile = self._codex_profile(scope="project")
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = mcp_config_manager.plan_apply(self.paths, profile, bridged=True)
        self.assertTrue(result.get("ok"), msg=result)
        plan = result["plan"]
        self.assertEqual(plan["scope"], "project")
        self.assertTrue(plan["bridged"])
        entry = plan["server_entry"]
        self.assertIn("AIRG_SOCKET_PATH", entry["env"])
        self.assertEqual(len(entry["args"]), 1)
        self.assertTrue(entry["args"][0].endswith("airg_stdio_bridge.py"))

    def test_plan_apply_bridged_preview_json_matches_server_entry(self) -> None:
        """plan_apply(bridged=True) preview_json reflects the shim entry."""
        with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
            result = mcp_config_manager.plan_apply(
                self.paths, self._codex_profile(), bridged=True
            )
        self.assertTrue(result.get("ok"), msg=result)
        plan = result["plan"]
        preview = plan["preview_json"]
        self.assertIn("mcpServers", preview)
        preview_entry = preview["mcpServers"]["ai-runtime-guard"]
        self.assertEqual(preview_entry, plan["server_entry"])


# ---------------------------------------------------------------------------
# Test 4 — mcp_config_manager.apply_mcp_config bridged=True writes shim config
# ---------------------------------------------------------------------------


class TestMCPConfigManagerBridgedApply(unittest.TestCase):
    """apply_mcp_config(bridged=True) writes the shim-pointing block to the target file."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.paths, self.workspace = _make_paths(self.base)
        self.home = self.base / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.state_dir = _state_dir_from_paths(self.paths)

        # Register the profile in agent_configs registry.
        result = agent_configs.upsert_profile(
            self.paths,
            {
                "profile_id": "p-codex-apply-bridge",
                "name": "Codex apply bridge",
                "agent_type": "codex",
                "agent_scope": "global",
                "workspace": str(self.workspace),
                "agent_id": "codex-apply-bridge-1",
            },
        )
        self.assertTrue(result.get("ok"), msg=result)
        self.profile = result["profile"]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_apply_mcp_config_bridged_writes_shim_command_to_toml(self) -> None:
        """apply_mcp_config(bridged=True) writes a TOML block with the shim command."""
        import tomllib

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
                result = mcp_config_manager.apply_mcp_config(
                    self.paths, self.profile, bridged=True
                )
        self.assertTrue(result.get("ok"), msg=result)

        # Read the written Codex global config.
        codex_cfg = self.home / ".codex" / "config.toml"
        self.assertTrue(codex_cfg.exists(), "codex config.toml should have been written")
        text = codex_cfg.read_text()
        parsed = tomllib.loads(text)

        mcp = parsed.get("mcp_servers", {}).get("ai-runtime-guard", {})
        command = mcp.get("command", "")
        args = mcp.get("args", [])
        env = mcp.get("env", {})

        # command: Python interpreter
        self.assertEqual(command, str(pathlib.Path(sys.executable).resolve()))
        # args: [path to shim]
        self.assertEqual(len(args), 1)
        self.assertTrue(args[0].endswith("airg_stdio_bridge.py"))
        # env: all three keys
        self.assertIn("AIRG_SOCKET_PATH", env)
        self.assertEqual(env.get("AIRG_AGENT_ID"), "codex-apply-bridge-1")
        self.assertIn("AIRG_WORKSPACE", env)

        # socket path matches convention
        socket_path = env["AIRG_SOCKET_PATH"]
        expected = _expected_socket_path(self.state_dir, "codex-apply-bridge-1")
        self.assertEqual(pathlib.Path(socket_path).resolve(), expected.resolve())

    def test_apply_mcp_config_default_writes_direct_command_to_toml(self) -> None:
        """apply_mcp_config default (bridged=False) writes the direct AIRG spawn (regression)."""
        import tomllib

        with patch("mcp_config_manager.pathlib.Path.home", return_value=self.home):
            with patch.dict("os.environ", {"AIRG_SERVER_COMMAND": ""}, clear=False):
                result = mcp_config_manager.apply_mcp_config(self.paths, self.profile)
        self.assertTrue(result.get("ok"), msg=result)

        codex_cfg = self.home / ".codex" / "config.toml"
        self.assertTrue(codex_cfg.exists())
        text = codex_cfg.read_text()
        parsed = tomllib.loads(text)

        mcp = parsed.get("mcp_servers", {}).get("ai-runtime-guard", {})
        args = mcp.get("args", [])
        env = mcp.get("env", {})

        self.assertIn("-m", args)
        self.assertIn("airg_cli", args)
        self.assertNotIn("AIRG_SOCKET_PATH", env)


# ---------------------------------------------------------------------------
# Test 5 — _agent_socket_path_for_config matches airg_cli._agent_socket_path
# ---------------------------------------------------------------------------


class TestSocketPathConventionParity(unittest.TestCase):
    """The path-convention helper in agent_configs must match airg_cli exactly."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = pathlib.Path(self.tmp.name) / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_socket_path_formula_matches_airg_cli(self) -> None:
        """_agent_socket_path_for_config and airg_cli._agent_socket_path agree."""
        import airg_cli

        for agent_id in ["default", "codex-1", "my.agent_id", "agent-test-123"]:
            expected = airg_cli._agent_socket_path(self.state_dir, agent_id)
            actual = agent_configs._agent_socket_path_for_config(self.state_dir, agent_id)
            self.assertEqual(
                actual.resolve(),
                expected.resolve(),
                f"Path mismatch for agent_id={agent_id!r}: {actual!r} != {expected!r}",
            )

    def test_socket_path_is_under_state_sockets_dir(self) -> None:
        """Socket path is under state_dir/sockets/."""
        result = agent_configs._agent_socket_path_for_config(self.state_dir, "my-agent")
        sockets_dir = self.state_dir / "sockets"
        self.assertTrue(
            str(result.resolve()).startswith(str(sockets_dir.resolve())),
            f"Socket path {result} should be under {sockets_dir}",
        )

    def test_socket_path_has_sock_suffix(self) -> None:
        """Socket path ends in .sock."""
        result = agent_configs._agent_socket_path_for_config(self.state_dir, "my-agent")
        self.assertEqual(result.suffix, ".sock")

    def test_socket_path_sanitizes_special_chars(self) -> None:
        """Characters outside [A-Za-z0-9_.-] are replaced with underscores."""
        result = agent_configs._agent_socket_path_for_config(self.state_dir, "agent/with spaces")
        name = result.name
        self.assertRegex(name, r"^[A-Za-z0-9_./_-]+\.sock$")
        self.assertNotIn(" ", name)
        self.assertNotIn("/", name[:-5])  # no slash in the stem


if __name__ == "__main__":
    unittest.main()
