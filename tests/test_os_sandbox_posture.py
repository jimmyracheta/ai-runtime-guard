"""
Tests for W2a: OS sandbox doctor checks, posture signal, and backend route.

Covers:
  * _os_sandbox_posture_signal() across all mode/launcher combinations
  * build_os_sandbox_posture() with mocked probe + selector
  * _doctor_os_sandbox_checks() — especially the enforce-but-no-launcher FAIL path
  * GET /api/os-sandbox/status — route returns expected JSON shape
"""

import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import agent_posture


# ---------------------------------------------------------------------------
# Helper probe factories
# ---------------------------------------------------------------------------

def _make_probe(*, landlock_abi=None, userns="no", bwrap=False, landrun=False):
    """Build a minimal probe_result dict like airg_sandbox_probe.run_probe()."""
    return {
        "platform": {"system": "Linux", "machine": "x86_64"},
        "landlock": {
            "available": landlock_abi is not None,
            "abi_version": landlock_abi,
            "note": f"ABI v{landlock_abi}" if landlock_abi else "not available",
        },
        "userns": {"verdict": userns, "evidence": {}},
        "launchers": {
            "bwrap": {"found": bwrap, "path": "/usr/bin/bwrap" if bwrap else None},
            "landrun": {"found": landrun, "path": "/usr/local/bin/landrun" if landrun else None},
            "nsjail": {"found": False, "path": None},
            "firejail": {"found": False, "path": None},
            "minijail0": {"found": False, "path": None},
        },
        "sandbox_exec": {"applicable": False},
        "seccomp": {"available": True, "evidence": {}},
        "recommendation": "test",
    }


def _make_macos_probe():
    """Build a minimal probe_result dict for macOS."""
    return {
        "platform": {"system": "Darwin", "machine": "arm64"},
        "landlock": {"available": False, "abi_version": None, "note": "Not Linux"},
        "userns": {"verdict": "not_applicable", "evidence": {}},
        "launchers": {
            "bwrap": {"found": False, "path": None},
            "landrun": {"found": False, "path": None},
            "nsjail": {"found": False, "path": None},
            "firejail": {"found": False, "path": None},
            "minijail0": {"found": False, "path": None},
        },
        "sandbox_exec": {
            "applicable": True,
            "found": True,
            "path": "/usr/bin/sandbox-exec",
        },
        "seccomp": {"available": False, "evidence": {"note": "Not Linux"}},
        "recommendation": "macOS host: sandbox-exec is the primary option.",
    }


# ---------------------------------------------------------------------------
# Tests for _os_sandbox_posture_signal()
# ---------------------------------------------------------------------------

class TestOsSandboxPostureSignal(unittest.TestCase):

    def test_mode_off_signal(self):
        cfg = {"mode": "off", "launcher": "auto", "on_setup_failure": "fail_closed"}
        probe = _make_probe(landlock_abi=4, userns="yes", bwrap=True, landrun=True)
        signal = agent_posture._os_sandbox_posture_signal(cfg, probe, None)
        self.assertEqual(signal["os_sandbox_mode"], "off")
        self.assertFalse(signal["os_sandbox_enabled"])
        self.assertFalse(signal["os_sandbox_confined_capable"])
        self.assertFalse(signal["os_sandbox_fail_closed_misconfig"])

    def test_monitor_mode_with_launcher(self):
        cfg = {"mode": "monitor", "launcher": "auto", "on_setup_failure": "fail_closed"}
        probe = _make_probe(landlock_abi=4, userns="yes", bwrap=True)
        signal = agent_posture._os_sandbox_posture_signal(cfg, probe, "bwrap")
        self.assertEqual(signal["os_sandbox_mode"], "monitor")
        self.assertTrue(signal["os_sandbox_enabled"])
        self.assertTrue(signal["os_sandbox_confined_capable"])
        self.assertFalse(signal["os_sandbox_fail_closed_misconfig"])
        self.assertEqual(signal["os_sandbox_launcher_selected"], "bwrap")

    def test_monitor_mode_without_launcher(self):
        cfg = {"mode": "monitor", "launcher": "auto", "on_setup_failure": "fail_closed"}
        probe = _make_probe()
        signal = agent_posture._os_sandbox_posture_signal(cfg, probe, None)
        self.assertEqual(signal["os_sandbox_mode"], "monitor")
        self.assertTrue(signal["os_sandbox_enabled"])
        self.assertFalse(signal["os_sandbox_confined_capable"])
        self.assertFalse(signal["os_sandbox_fail_closed_misconfig"])
        self.assertIsNone(signal["os_sandbox_launcher_selected"])

    def test_enforce_with_launcher_ok(self):
        cfg = {"mode": "enforce", "launcher": "auto", "on_setup_failure": "fail_closed"}
        signal = agent_posture._os_sandbox_posture_signal(cfg, {}, "landrun")
        self.assertEqual(signal["os_sandbox_mode"], "enforce")
        self.assertTrue(signal["os_sandbox_enabled"])
        self.assertTrue(signal["os_sandbox_confined_capable"])
        self.assertFalse(signal["os_sandbox_fail_closed_misconfig"])
        self.assertEqual(signal["os_sandbox_launcher_selected"], "landrun")

    def test_enforce_no_launcher_fail_closed_misconfig(self):
        """This is the key operational guardrail test."""
        cfg = {"mode": "enforce", "launcher": "auto", "on_setup_failure": "fail_closed"}
        probe = _make_probe()  # no launchers
        signal = agent_posture._os_sandbox_posture_signal(cfg, probe, None)
        self.assertEqual(signal["os_sandbox_mode"], "enforce")
        self.assertTrue(signal["os_sandbox_enabled"])
        self.assertFalse(signal["os_sandbox_confined_capable"])
        self.assertTrue(signal["os_sandbox_fail_closed_misconfig"],
                        "Must flag fail_closed_misconfig when enforce+no launcher+fail_closed")

    def test_enforce_no_launcher_warn_and_run_not_misconfig(self):
        """warn_and_run_unconfined is an explicit operator opt-out, NOT a misconfiguration."""
        cfg = {"mode": "enforce", "launcher": "auto",
               "on_setup_failure": "warn_and_run_unconfined"}
        probe = _make_probe()
        signal = agent_posture._os_sandbox_posture_signal(cfg, probe, None)
        self.assertFalse(signal["os_sandbox_fail_closed_misconfig"],
                         "warn_and_run_unconfined should NOT be flagged as misconfig")

    def test_probe_summary_landlock_data(self):
        probe = _make_probe(landlock_abi=4, userns="yes", bwrap=True)
        cfg = {"mode": "off", "launcher": "auto", "on_setup_failure": "fail_closed"}
        signal = agent_posture._os_sandbox_posture_signal(cfg, probe, None)
        summary = signal["os_sandbox_probe_summary"]
        self.assertTrue(summary["landlock_available"])
        self.assertEqual(summary["landlock_abi_version"], 4)
        self.assertEqual(summary["userns_verdict"], "yes")
        self.assertTrue(summary["launchers_found"]["bwrap"])

    def test_empty_probe_safe(self):
        cfg = {"mode": "off", "launcher": "auto", "on_setup_failure": "fail_closed"}
        signal = agent_posture._os_sandbox_posture_signal(cfg, {}, None)
        summary = signal["os_sandbox_probe_summary"]
        self.assertFalse(summary["landlock_available"])
        self.assertIsNone(summary["landlock_abi_version"])

    def test_none_cfg_safe(self):
        signal = agent_posture._os_sandbox_posture_signal(None, {}, None)
        self.assertEqual(signal["os_sandbox_mode"], "off")

    def test_launcher_pref_preserved(self):
        cfg = {"mode": "enforce", "launcher": "landrun", "on_setup_failure": "fail_closed"}
        signal = agent_posture._os_sandbox_posture_signal(cfg, {}, "landrun")
        self.assertEqual(signal["os_sandbox_launcher_pref"], "landrun")
        self.assertEqual(signal["os_sandbox_launcher_selected"], "landrun")


# ---------------------------------------------------------------------------
# Tests for build_os_sandbox_posture() — mock probe + selector
# ---------------------------------------------------------------------------

class TestBuildOsSandboxPosture(unittest.TestCase):

    def _patched_posture(self, os_sandbox_cfg: dict, probe_result: dict,
                         launcher=None):
        """Call build_os_sandbox_posture with mocked probe + selector."""
        mock_sl = MagicMock()
        mock_sl.select_launcher.return_value = launcher

        with patch.dict("sys.modules", {"sandbox_launcher": mock_sl}):
            return agent_posture.build_os_sandbox_posture(
                os_sandbox_cfg=os_sandbox_cfg,
                probe_result=probe_result,
            )

    def test_off_mode_returns_gray(self):
        result = self._patched_posture(
            {"mode": "off", "launcher": "auto", "on_setup_failure": "fail_closed"},
            _make_probe(),
            launcher=None,
        )
        self.assertEqual(result["status"], "gray")
        self.assertIn("disabled", result["rationale"])
        self.assertIn("signal", result)

    def test_enforce_with_launcher_returns_green(self):
        result = self._patched_posture(
            {"mode": "enforce", "launcher": "auto", "on_setup_failure": "fail_closed"},
            _make_probe(landlock_abi=4, userns="yes", bwrap=True),
            launcher="bwrap",
        )
        self.assertEqual(result["status"], "green")
        self.assertIn("bwrap", result["rationale"])

    def test_enforce_no_launcher_fail_closed_returns_red(self):
        """Critical path: enforce + no launcher + fail_closed → red status."""
        result = self._patched_posture(
            {"mode": "enforce", "launcher": "auto", "on_setup_failure": "fail_closed"},
            _make_probe(),  # no launchers found
            launcher=None,
        )
        self.assertEqual(result["status"], "red")
        self.assertIn("fail", result["rationale"].lower())
        self.assertTrue(result["signal"]["os_sandbox_fail_closed_misconfig"])

    def test_enforce_no_launcher_warn_returns_yellow(self):
        result = self._patched_posture(
            {"mode": "enforce", "launcher": "auto",
             "on_setup_failure": "warn_and_run_unconfined"},
            _make_probe(),
            launcher=None,
        )
        self.assertEqual(result["status"], "yellow")
        self.assertFalse(result["signal"]["os_sandbox_fail_closed_misconfig"])

    def test_monitor_with_launcher_returns_yellow(self):
        result = self._patched_posture(
            {"mode": "monitor", "launcher": "auto", "on_setup_failure": "fail_closed"},
            _make_probe(landlock_abi=3, landrun=True),
            launcher="landrun",
        )
        self.assertEqual(result["status"], "yellow")
        self.assertIn("monitor", result["rationale"])

    def test_monitor_without_launcher_returns_yellow(self):
        result = self._patched_posture(
            {"mode": "monitor", "launcher": "auto", "on_setup_failure": "fail_closed"},
            _make_probe(),
            launcher=None,
        )
        self.assertEqual(result["status"], "yellow")

    def test_result_shape(self):
        result = self._patched_posture(
            {"mode": "off", "launcher": "auto", "on_setup_failure": "fail_closed"},
            {},
            launcher=None,
        )
        self.assertIn("status", result)
        self.assertIn("rationale", result)
        self.assertIn("signal", result)
        signal = result["signal"]
        for key in ("os_sandbox_mode", "os_sandbox_enabled", "os_sandbox_launcher_selected",
                    "os_sandbox_confined_capable", "os_sandbox_fail_closed_misconfig",
                    "os_sandbox_on_setup_failure", "os_sandbox_probe_summary"):
            self.assertIn(key, signal, f"signal missing key: {key}")

    def test_sandbox_launcher_import_failure_safe(self):
        """If sandbox_launcher cannot be imported, posture should still succeed."""
        with patch.dict("sys.modules", {"sandbox_launcher": None}):
            result = agent_posture.build_os_sandbox_posture(
                os_sandbox_cfg={"mode": "off", "launcher": "auto",
                                "on_setup_failure": "fail_closed"},
                probe_result=_make_probe(),
            )
        self.assertIn("status", result)


# ---------------------------------------------------------------------------
# Tests for _doctor_os_sandbox_checks()
# ---------------------------------------------------------------------------

class TestDoctorOsSandboxChecks(unittest.TestCase):

    def _run_checks(self, *, mode="off", launcher_pref="auto",
                    on_setup_failure="fail_closed", probe_result=None,
                    selected_launcher=None, probe_error=None):
        """Run _doctor_os_sandbox_checks with mocked probe + selector + policy."""
        import airg_cli

        if probe_result is None and probe_error is None:
            probe_result = _make_probe()

        issues: list = []
        warnings: list = []
        policy_doc = {
            "os_sandbox": {
                "mode": mode,
                "launcher": launcher_pref,
                "on_setup_failure": on_setup_failure,
            }
        }

        # Build a mock probe module
        mock_probe_mod = MagicMock()
        if probe_error:
            mock_probe_mod.run_probe.side_effect = Exception(probe_error)
        else:
            mock_probe_mod.run_probe.return_value = probe_result

        mock_sl = MagicMock()
        mock_sl.select_launcher.return_value = selected_launcher

        with patch.dict("sys.modules", {
            "airg_sandbox_probe": mock_probe_mod,
            "sandbox_launcher": mock_sl,
        }):
            # Mock _resolve_paths to return a temp policy path
            with tempfile.TemporaryDirectory() as tmpdir:
                policy_path = pathlib.Path(tmpdir) / "policy.json"
                policy_path.write_text(json.dumps(policy_doc))
                fake_paths = {
                    "policy_path": policy_path,
                    "approval_db_path": pathlib.Path(tmpdir) / "approvals.db",
                    "approval_hmac_key_path": pathlib.Path(tmpdir) / "key",
                    "log_path": pathlib.Path(tmpdir) / "activity.log",
                    "reports_db_path": pathlib.Path(tmpdir) / "reports.db",
                }
                with patch.object(airg_cli, "_resolve_paths", return_value=fake_paths):
                    # Capture stdout
                    buf = io.StringIO()
                    import contextlib
                    with contextlib.redirect_stdout(buf):
                        airg_cli._doctor_os_sandbox_checks(issues, warnings)

        output = buf.getvalue()
        return issues, warnings, output

    def test_mode_off_no_issues(self):
        issues, warnings, output = self._run_checks(mode="off")
        self.assertEqual(issues, [])
        self.assertIn("not enabled", output)

    def test_monitor_no_issues(self):
        issues, warnings, output = self._run_checks(
            mode="monitor",
            probe_result=_make_probe(landlock_abi=3, landrun=True),
            selected_launcher="landrun",
        )
        self.assertEqual(issues, [])
        self.assertIn("monitor", output)

    def test_enforce_with_launcher_no_issues(self):
        issues, warnings, output = self._run_checks(
            mode="enforce",
            probe_result=_make_probe(userns="yes", bwrap=True),
            selected_launcher="bwrap",
        )
        self.assertEqual(issues, [])
        self.assertIn("bwrap", output)

    def test_enforce_no_launcher_fail_closed_is_error(self):
        """Critical: enforce + no launcher + fail_closed MUST produce an issue (not just warning)."""
        issues, warnings, output = self._run_checks(
            mode="enforce",
            on_setup_failure="fail_closed",
            probe_result=_make_probe(),  # no launchers
            selected_launcher=None,
        )
        self.assertGreater(len(issues), 0, "Must have at least one issue for fail-closed misconfig")
        combined_issues = " ".join(issues).lower()
        self.assertIn("fail", combined_issues)
        self.assertIn("misconfig", combined_issues.lower() + output.lower())

    def test_enforce_no_launcher_warn_is_warning_not_error(self):
        """warn_and_run_unconfined should be a warning, not an error."""
        issues, warnings_list, output = self._run_checks(
            mode="enforce",
            on_setup_failure="warn_and_run_unconfined",
            probe_result=_make_probe(),
            selected_launcher=None,
        )
        self.assertEqual(issues, [], "warn_and_run_unconfined must not produce an error")
        self.assertGreater(len(warnings_list), 0, "Must produce at least one warning")

    def test_probe_failure_is_warning(self):
        issues, warnings_list, output = self._run_checks(
            probe_error="probe import failed",
        )
        combined = " ".join(warnings_list).lower()
        self.assertIn("probe", combined)

    def test_probe_output_shows_launcher_found(self):
        _, _, output = self._run_checks(
            mode="off",
            probe_result=_make_probe(landlock_abi=4, userns="yes", bwrap=True),
        )
        self.assertIn("FOUND", output)
        self.assertIn("bwrap", output)

    def test_mode_line_printed(self):
        _, _, output = self._run_checks(mode="monitor")
        self.assertIn("os_sandbox.mode", output)
        self.assertIn("monitor", output)


# ---------------------------------------------------------------------------
# Tests for GET /api/os-sandbox/status route
# ---------------------------------------------------------------------------

class TestOsSandboxStatusRoute(unittest.TestCase):
    """Unit-test the route handler function directly (no live Flask server needed)."""

    def _call_route(self, mock_posture_result=None):
        """Import the Flask app and call the handler through the test client."""
        # We need to import the backend_flask app. This requires all its module-level
        # side-effects (approvals.init, reports.init, etc.) to succeed, so we patch
        # them with a minimal temp environment.
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            base = pathlib.Path(tmpdir)
            policy_path = base / "policy.json"
            policy_path.write_text(json.dumps({
                "blocked": {"commands": [], "paths": [], "extensions": []},
                "requires_confirmation": {"commands": [], "paths": [],
                                          "session_whitelist_enabled": True,
                                          "approval_security": {
                                              "max_failed_attempts_per_token": 5,
                                              "failed_attempt_window_seconds": 600,
                                              "token_ttl_seconds": 600,
                                          }},
                "allowed": {"paths_whitelist": [], "max_directory_depth": 100},
                "network": {"enforcement_mode": "off", "commands": [],
                            "allowed_domains": [], "blocked_domains": [],
                            "block_unknown_domains": False},
                "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000,
                               "shell_workspace_containment": {"mode": "off",
                                                               "exempt_commands": [],
                                                               "log_paths": True}},
                "backup_access": {"block_agent_tools": True},
                "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
                "audit": {"backup_enabled": True, "backup_on_content_change_only": True,
                          "max_versions_per_file": 5, "backup_root": str(base / "backups"),
                          "backup_retention_days": 30, "log_level": "verbose",
                          "redact_patterns": []},
                "reports": {"enabled": True, "ingest_poll_interval_seconds": 5,
                            "reconcile_interval_seconds": 3600, "retention_days": 30,
                            "max_db_size_mb": 200, "prune_interval_seconds": 86400},
                "telemetry": {"enabled": False, "endpoint": "https://example.com",
                              "last_payload_generated_date": "",
                              "last_payload_uploaded_at": "",
                              "last_sent_date": ""},
                "script_sentinel": {"enabled": False, "mode": "match_original",
                                    "scan_mode": "exec_context",
                                    "max_scan_bytes": 1048576, "include_wrappers": True},
                "os_sandbox": {"enabled": False, "mode": "off", "launcher": "auto",
                               "on_setup_failure": "fail_closed", "network_mode": "none",
                               "allowed_tcp_ports": [], "credential_carve_outs": [],
                               "filesystem": {"workspace_root": "", "readable_paths": [],
                                              "read_exec_paths": [], "writable_paths": ["/tmp"],
                                              "bridge_socket_path": ""}},
                "agent_overrides": {},
            }))

            env_overrides = {
                "AIRG_POLICY_PATH": str(policy_path),
                "AIRG_APPROVAL_DB_PATH": str(base / "approvals.db"),
                "AIRG_APPROVAL_HMAC_KEY_PATH": str(base / "key"),
                "AIRG_LOG_PATH": str(base / "activity.log"),
                "AIRG_REPORTS_DB_PATH": str(base / "reports.db"),
                "AIRG_WORKSPACE": str(base / "workspace"),
                "AIRG_CATALOG_PATH": str(base / "catalog.json"),
            }
            # Write an empty catalog
            (base / "catalog.json").write_text("{}")

            old_env = {k: os.environ.get(k) for k in env_overrides}
            os.environ.update(env_overrides)
            try:
                # Force reimport of the backend module each time by removing from cache
                for mod_name in list(sys.modules.keys()):
                    if "backend_flask" in mod_name or "ui.backend_flask" in mod_name:
                        del sys.modules[mod_name]

                # Patch build_os_sandbox_posture to return a controlled value
                if mock_posture_result is not None:
                    with patch.object(agent_posture, "build_os_sandbox_posture",
                                      return_value=mock_posture_result):
                        from ui import backend_flask as bflask
                        client = bflask.app.test_client()
                        response = client.get(
                            "/api/os-sandbox/status",
                            headers={"Host": "127.0.0.1:5001"},
                        )
                else:
                    with patch.object(agent_posture, "build_os_sandbox_posture",
                                      return_value={
                                          "status": "gray",
                                          "rationale": "off",
                                          "signal": {"os_sandbox_mode": "off"},
                                      }):
                        from ui import backend_flask as bflask
                        client = bflask.app.test_client()
                        response = client.get(
                            "/api/os-sandbox/status",
                            headers={"Host": "127.0.0.1:5001"},
                        )
            finally:
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                # Clean up module cache again
                for mod_name in list(sys.modules.keys()):
                    if "backend_flask" in mod_name or "ui.backend_flask" in mod_name:
                        del sys.modules[mod_name]

        return response

    def test_route_returns_200_ok(self):
        resp = self._call_route()
        self.assertEqual(resp.status_code, 200)

    def test_route_returns_json_shape(self):
        mock_posture = {
            "status": "green",
            "rationale": "Enforcing with bwrap",
            "signal": {
                "os_sandbox_mode": "enforce",
                "os_sandbox_enabled": True,
                "os_sandbox_launcher_selected": "bwrap",
                "os_sandbox_confined_capable": True,
                "os_sandbox_fail_closed_misconfig": False,
                "os_sandbox_on_setup_failure": "fail_closed",
                "os_sandbox_probe_summary": {
                    "landlock_available": False,
                    "landlock_abi_version": None,
                    "userns_verdict": "yes",
                    "launchers_found": {"bwrap": True},
                },
            },
        }
        resp = self._call_route(mock_posture_result=mock_posture)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data.get("ok"))
        self.assertIn("status", data)
        self.assertIn("rationale", data)
        self.assertIn("signal", data)
        signal = data["signal"]
        self.assertEqual(signal["os_sandbox_mode"], "enforce")
        self.assertEqual(data["status"], "green")

    def test_route_options_returns_204(self):
        import os, tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            base = pathlib.Path(tmpdir)
            # minimal policy setup
            (base / "catalog.json").write_text("{}")
            policy_path = base / "policy.json"
            policy_path.write_text(json.dumps({
                "blocked": {"commands": [], "paths": [], "extensions": []},
                "requires_confirmation": {"commands": [], "paths": [],
                                          "session_whitelist_enabled": True,
                                          "approval_security": {
                                              "max_failed_attempts_per_token": 5,
                                              "failed_attempt_window_seconds": 600,
                                              "token_ttl_seconds": 600}},
                "allowed": {"paths_whitelist": [], "max_directory_depth": 100},
                "network": {"enforcement_mode": "off", "commands": [],
                            "allowed_domains": [], "blocked_domains": [],
                            "block_unknown_domains": False},
                "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000,
                               "shell_workspace_containment": {"mode": "off",
                                                               "exempt_commands": [],
                                                               "log_paths": True}},
                "backup_access": {"block_agent_tools": True},
                "restore": {"require_dry_run_before_apply": True,
                            "confirmation_ttl_seconds": 300},
                "audit": {"backup_enabled": True, "backup_on_content_change_only": True,
                          "max_versions_per_file": 5, "backup_root": str(base / "backups"),
                          "backup_retention_days": 30, "log_level": "verbose",
                          "redact_patterns": []},
                "reports": {"enabled": True, "ingest_poll_interval_seconds": 5,
                            "reconcile_interval_seconds": 3600, "retention_days": 30,
                            "max_db_size_mb": 200, "prune_interval_seconds": 86400},
                "telemetry": {"enabled": False, "endpoint": "https://example.com",
                              "last_payload_generated_date": "", "last_payload_uploaded_at": "",
                              "last_sent_date": ""},
                "script_sentinel": {"enabled": False, "mode": "match_original",
                                    "scan_mode": "exec_context", "max_scan_bytes": 1048576,
                                    "include_wrappers": True},
                "os_sandbox": {"enabled": False, "mode": "off", "launcher": "auto",
                               "on_setup_failure": "fail_closed", "network_mode": "none",
                               "allowed_tcp_ports": [], "credential_carve_outs": [],
                               "filesystem": {"workspace_root": "", "readable_paths": [],
                                              "read_exec_paths": [], "writable_paths": ["/tmp"],
                                              "bridge_socket_path": ""}},
                "agent_overrides": {},
            }))

            env_overrides = {
                "AIRG_POLICY_PATH": str(policy_path),
                "AIRG_APPROVAL_DB_PATH": str(base / "approvals.db"),
                "AIRG_APPROVAL_HMAC_KEY_PATH": str(base / "key"),
                "AIRG_LOG_PATH": str(base / "activity.log"),
                "AIRG_REPORTS_DB_PATH": str(base / "reports.db"),
                "AIRG_WORKSPACE": str(base / "workspace"),
                "AIRG_CATALOG_PATH": str(base / "catalog.json"),
            }
            old_env = {k: os.environ.get(k) for k in env_overrides}
            os.environ.update(env_overrides)
            try:
                for mod_name in list(sys.modules.keys()):
                    if "backend_flask" in mod_name or "ui.backend_flask" in mod_name:
                        del sys.modules[mod_name]
                from ui import backend_flask as bflask
                client = bflask.app.test_client()
                resp = client.options(
                    "/api/os-sandbox/status",
                    headers={"Host": "127.0.0.1:5001"},
                )
                self.assertEqual(resp.status_code, 204)
            finally:
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                for mod_name in list(sys.modules.keys()):
                    if "backend_flask" in mod_name or "ui.backend_flask" in mod_name:
                        del sys.modules[mod_name]

    def test_route_blocked_for_non_localhost(self):
        """Non-localhost Host header must be rejected by the security guard."""
        import os, tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            base = pathlib.Path(tmpdir)
            (base / "catalog.json").write_text("{}")
            policy_path = base / "policy.json"
            policy_path.write_text(json.dumps({
                "blocked": {"commands": [], "paths": [], "extensions": []},
                "requires_confirmation": {"commands": [], "paths": [],
                                          "session_whitelist_enabled": True,
                                          "approval_security": {
                                              "max_failed_attempts_per_token": 5,
                                              "failed_attempt_window_seconds": 600,
                                              "token_ttl_seconds": 600}},
                "allowed": {"paths_whitelist": [], "max_directory_depth": 100},
                "network": {"enforcement_mode": "off", "commands": [],
                            "allowed_domains": [], "blocked_domains": [],
                            "block_unknown_domains": False},
                "execution": {"max_command_timeout_seconds": 30, "max_output_chars": 200000,
                               "shell_workspace_containment": {"mode": "off",
                                                               "exempt_commands": [],
                                                               "log_paths": True}},
                "backup_access": {"block_agent_tools": True},
                "restore": {"require_dry_run_before_apply": True,
                            "confirmation_ttl_seconds": 300},
                "audit": {"backup_enabled": True, "backup_on_content_change_only": True,
                          "max_versions_per_file": 5, "backup_root": str(base / "backups"),
                          "backup_retention_days": 30, "log_level": "verbose",
                          "redact_patterns": []},
                "reports": {"enabled": True, "ingest_poll_interval_seconds": 5,
                            "reconcile_interval_seconds": 3600, "retention_days": 30,
                            "max_db_size_mb": 200, "prune_interval_seconds": 86400},
                "telemetry": {"enabled": False, "endpoint": "https://example.com",
                              "last_payload_generated_date": "", "last_payload_uploaded_at": "",
                              "last_sent_date": ""},
                "script_sentinel": {"enabled": False, "mode": "match_original",
                                    "scan_mode": "exec_context", "max_scan_bytes": 1048576,
                                    "include_wrappers": True},
                "os_sandbox": {"enabled": False, "mode": "off", "launcher": "auto",
                               "on_setup_failure": "fail_closed", "network_mode": "none",
                               "allowed_tcp_ports": [], "credential_carve_outs": [],
                               "filesystem": {"workspace_root": "", "readable_paths": [],
                                              "read_exec_paths": [], "writable_paths": ["/tmp"],
                                              "bridge_socket_path": ""}},
                "agent_overrides": {},
            }))
            env_overrides = {
                "AIRG_POLICY_PATH": str(policy_path),
                "AIRG_APPROVAL_DB_PATH": str(base / "approvals.db"),
                "AIRG_APPROVAL_HMAC_KEY_PATH": str(base / "key"),
                "AIRG_LOG_PATH": str(base / "activity.log"),
                "AIRG_REPORTS_DB_PATH": str(base / "reports.db"),
                "AIRG_WORKSPACE": str(base / "workspace"),
                "AIRG_CATALOG_PATH": str(base / "catalog.json"),
            }
            old_env = {k: os.environ.get(k) for k in env_overrides}
            os.environ.update(env_overrides)
            try:
                for mod_name in list(sys.modules.keys()):
                    if "backend_flask" in mod_name or "ui.backend_flask" in mod_name:
                        del sys.modules[mod_name]
                from ui import backend_flask as bflask
                client = bflask.app.test_client()
                resp = client.get(
                    "/api/os-sandbox/status",
                    headers={"Host": "evil.example.com"},
                )
                self.assertEqual(resp.status_code, 403)
            finally:
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                for mod_name in list(sys.modules.keys()):
                    if "backend_flask" in mod_name or "ui.backend_flask" in mod_name:
                        del sys.modules[mod_name]


if __name__ == "__main__":
    unittest.main()
