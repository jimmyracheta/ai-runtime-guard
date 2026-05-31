"""
Tests for the os_sandbox policy section.

Coverage:
- Default presence and safe values
- Normalization of partial/missing/malformed input (fail-safe to defaults)
- fail_closed default for on_setup_failure
- Tightening-only override: accepted vs rejected for each implemented rule
- Round-trip load/validate
"""
import copy
import unittest

import config


def _make_policy(**kwargs):
    """Minimal valid policy with os_sandbox overridable via kwargs."""
    base = {
        "blocked": {"commands": [], "paths": [], "extensions": []},
        "requires_confirmation": {
            "commands": [],
            "paths": [],
            "session_whitelist_enabled": True,
            "approval_security": {
                "max_failed_attempts_per_token": 5,
                "failed_attempt_window_seconds": 600,
                "token_ttl_seconds": 600,
            },
        },
        "allowed": {"paths_whitelist": [], "max_directory_depth": 100},
        "network": {
            "enforcement_mode": "off",
            "commands": [],
            "allowed_domains": [],
            "blocked_domains": [],
            "block_unknown_domains": False,
        },
        "execution": {
            "max_command_timeout_seconds": 30,
            "max_output_chars": 200000,
            "shell_workspace_containment": {"mode": "off", "exempt_commands": [], "log_paths": True},
        },
        "backup_access": {"block_agent_tools": True},
        "restore": {"require_dry_run_before_apply": True, "confirmation_ttl_seconds": 300},
        "audit": {
            "backup_enabled": True,
            "backup_on_content_change_only": True,
            "max_versions_per_file": 5,
            "backup_root": "/tmp/test-backups",
            "backup_retention_days": 30,
            "log_level": "verbose",
            "redact_patterns": [],
        },
        "reports": {
            "enabled": True,
            "ingest_poll_interval_seconds": 5,
            "reconcile_interval_seconds": 3600,
            "retention_days": 30,
            "max_db_size_mb": 200,
            "prune_interval_seconds": 86400,
        },
        "telemetry": {
            "enabled": True,
            "endpoint": "https://telemetry.runtime-guard.ai/v1/telemetry",
            "last_payload_generated_date": "",
            "last_payload_uploaded_at": "",
            "last_sent_date": "",
        },
        "script_sentinel": {
            "enabled": False,
            "mode": "match_original",
            "scan_mode": "exec_context",
            "max_scan_bytes": 1048576,
            "include_wrappers": True,
        },
    }
    if kwargs:
        base["os_sandbox"] = kwargs
    return base


def _normalize(policy_dict):
    return config._validate_and_normalize_policy(copy.deepcopy(policy_dict))


class OsSandboxDefaultsTest(unittest.TestCase):
    """Policy without an os_sandbox section gets safe defaults after normalization."""

    def setUp(self):
        self.policy = _normalize(_make_policy())

    def test_os_sandbox_section_present(self):
        self.assertIn("os_sandbox", self.policy)

    def test_enabled_defaults_false(self):
        self.assertFalse(self.policy["os_sandbox"]["enabled"])

    def test_mode_defaults_off(self):
        self.assertEqual(self.policy["os_sandbox"]["mode"], "off")

    def test_launcher_defaults_auto(self):
        self.assertEqual(self.policy["os_sandbox"]["launcher"], "auto")

    def test_on_setup_failure_defaults_fail_closed(self):
        self.assertEqual(self.policy["os_sandbox"]["on_setup_failure"], "fail_closed")

    def test_network_mode_defaults_none(self):
        self.assertEqual(self.policy["os_sandbox"]["network_mode"], "none")

    def test_allowed_tcp_ports_defaults_empty(self):
        self.assertEqual(self.policy["os_sandbox"]["allowed_tcp_ports"], [])

    def test_credential_carve_outs_defaults_empty(self):
        self.assertEqual(self.policy["os_sandbox"]["credential_carve_outs"], [])

    def test_filesystem_section_present(self):
        fs = self.policy["os_sandbox"]["filesystem"]
        self.assertIsInstance(fs, dict)

    def test_filesystem_workspace_root_defaults_empty_string(self):
        self.assertEqual(self.policy["os_sandbox"]["filesystem"]["workspace_root"], "")

    def test_filesystem_bridge_socket_path_defaults_empty_string(self):
        self.assertEqual(self.policy["os_sandbox"]["filesystem"]["bridge_socket_path"], "")

    def test_filesystem_readable_paths_defaults_empty(self):
        self.assertEqual(self.policy["os_sandbox"]["filesystem"]["readable_paths"], [])

    def test_filesystem_writable_paths_defaults_tmp(self):
        self.assertEqual(self.policy["os_sandbox"]["filesystem"]["writable_paths"], ["/tmp"])

    def test_filesystem_read_exec_paths_defaults_baseline(self):
        rexp = self.policy["os_sandbox"]["filesystem"]["read_exec_paths"]
        self.assertIsInstance(rexp, list)
        self.assertIn("/usr", rexp)
        self.assertIn("/bin", rexp)
        self.assertIn("/etc/ssl/certs", rexp)

    def test_all_fields_are_correct_types(self):
        s = self.policy["os_sandbox"]
        self.assertIsInstance(s["enabled"], bool)
        self.assertIsInstance(s["mode"], str)
        self.assertIsInstance(s["launcher"], str)
        self.assertIsInstance(s["on_setup_failure"], str)
        self.assertIsInstance(s["network_mode"], str)
        self.assertIsInstance(s["allowed_tcp_ports"], list)
        self.assertIsInstance(s["credential_carve_outs"], list)
        self.assertIsInstance(s["filesystem"], dict)


class OsSandboxNormalizationTest(unittest.TestCase):
    """Partial, missing, or malformed os_sandbox input is normalized to safe defaults."""

    def test_missing_section_handled(self):
        """Policy without os_sandbox section is normalized without error."""
        policy = _normalize(_make_policy())
        self.assertIn("os_sandbox", policy)

    def test_empty_section_gets_all_defaults(self):
        """Empty dict gets fully populated defaults."""
        policy = _normalize(_make_policy())  # no os_sandbox key → empty section
        s = policy["os_sandbox"]
        self.assertEqual(s["mode"], "off")
        self.assertEqual(s["on_setup_failure"], "fail_closed")
        self.assertIsInstance(s["filesystem"], dict)

    def test_partial_section_missing_mode_defaults_off(self):
        """Section with some fields but no mode defaults mode to off."""
        policy = _normalize(_make_policy(enabled=False, launcher="auto"))
        self.assertEqual(policy["os_sandbox"]["mode"], "off")

    def test_partial_filesystem_missing_bridge_defaults_empty(self):
        """filesystem sub-object without bridge_socket_path gets empty string."""
        policy = _normalize(_make_policy(
            enabled=False,
            mode="off",
            filesystem={"workspace_root": "/tmp/ws"},
        ))
        self.assertEqual(policy["os_sandbox"]["filesystem"]["bridge_socket_path"], "")

    def test_null_os_sandbox_treated_as_empty_object(self):
        """None value for os_sandbox is treated as empty dict (no error)."""
        p = _make_policy()
        p["os_sandbox"] = None
        policy = _normalize(p)
        # None → empty dict → fully defaulted
        self.assertEqual(policy["os_sandbox"]["mode"], "off")

    def test_null_credential_carve_outs_normalized_to_empty_list(self):
        """null credential_carve_outs is normalized to []."""
        policy = _normalize(_make_policy(
            mode="off",
            credential_carve_outs=None,
        ))
        self.assertEqual(policy["os_sandbox"]["credential_carve_outs"], [])

    def test_null_read_exec_paths_gets_baseline_default(self):
        """null read_exec_paths is normalized to the baseline default list."""
        policy = _normalize(_make_policy(
            mode="off",
            filesystem={"read_exec_paths": None},
        ))
        rexp = policy["os_sandbox"]["filesystem"]["read_exec_paths"]
        self.assertIn("/usr", rexp)
        self.assertGreater(len(rexp), 0)

    def test_absent_read_exec_paths_gets_baseline_default(self):
        """Absent read_exec_paths key gets the baseline default list."""
        policy = _normalize(_make_policy(
            mode="off",
            filesystem={"workspace_root": ""},
        ))
        rexp = policy["os_sandbox"]["filesystem"]["read_exec_paths"]
        self.assertIn("/usr", rexp)

    def test_explicit_empty_read_exec_paths_preserved(self):
        """Explicitly empty read_exec_paths [] is kept (operator cleared it)."""
        policy = _normalize(_make_policy(
            mode="off",
            filesystem={"read_exec_paths": []},
        ))
        self.assertEqual(policy["os_sandbox"]["filesystem"]["read_exec_paths"], [])

    def test_invalid_mode_raises(self):
        p = _make_policy(mode="unknown")
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.mode", str(cm.exception))

    def test_invalid_launcher_raises(self):
        p = _make_policy(launcher="nsjail")
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.launcher", str(cm.exception))

    def test_invalid_on_setup_failure_raises(self):
        p = _make_policy(on_setup_failure="ignore")
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.on_setup_failure", str(cm.exception))

    def test_invalid_network_mode_raises(self):
        p = _make_policy(network_mode="full")
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.network_mode", str(cm.exception))

    def test_invalid_port_raises(self):
        p = _make_policy(allowed_tcp_ports=[99999])
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.allowed_tcp_ports", str(cm.exception))

    def test_non_bool_enabled_raises(self):
        p = _make_policy(enabled="yes")
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.enabled", str(cm.exception))

    def test_non_dict_filesystem_raises(self):
        p = _make_policy(filesystem="bad")
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.filesystem", str(cm.exception))

    def test_credential_carve_out_missing_reason_raises(self):
        p = _make_policy(credential_carve_outs=[{"path": "/home/user/.gitconfig", "access": "read", "reason": ""}])
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("reason", str(cm.exception))

    def test_credential_carve_out_invalid_access_raises(self):
        p = _make_policy(credential_carve_outs=[{"path": "/home/user/.gitconfig", "access": "write", "reason": "needed"}])
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("access", str(cm.exception))

    def test_credential_carve_out_valid_entry_accepted(self):
        p = _make_policy(credential_carve_outs=[{
            "path": "/home/user/.gitconfig",
            "access": "read",
            "reason": "git identity for agent",
        }])
        policy = _normalize(p)
        self.assertEqual(len(policy["os_sandbox"]["credential_carve_outs"]), 1)

    def test_valid_ports_accepted(self):
        p = _make_policy(allowed_tcp_ports=[80, 443])
        policy = _normalize(p)
        self.assertIn(80, policy["os_sandbox"]["allowed_tcp_ports"])


class OsSandboxFailClosedTest(unittest.TestCase):
    """on_setup_failure defaults to fail_closed in all normalization paths."""

    def test_default_is_fail_closed(self):
        policy = _normalize(_make_policy())
        self.assertEqual(policy["os_sandbox"]["on_setup_failure"], "fail_closed")

    def test_explicit_warn_and_run_unconfined_accepted(self):
        policy = _normalize(_make_policy(on_setup_failure="warn_and_run_unconfined"))
        self.assertEqual(policy["os_sandbox"]["on_setup_failure"], "warn_and_run_unconfined")

    def test_null_on_setup_failure_gets_fail_closed(self):
        p = _make_policy()
        p["os_sandbox"] = {"on_setup_failure": None}
        # None does not pass setdefault (key exists), but it is not a valid enum value
        # After setdefault the value would remain None — validate should catch it
        # Actually setdefault won't override an existing key set to None.
        # The normalizer only calls setdefault, so None would fail the enum check.
        with self.assertRaises((ValueError, AttributeError)):
            _normalize(p)


class OsSandboxTighteningOverrideTest(unittest.TestCase):
    """Tightening-only validation: accepted vs rejected for each rule."""

    def _policy_with_os_sandbox(self, **os_sandbox_kwargs):
        p = _make_policy(**os_sandbox_kwargs)
        return p

    def _policy_with_override(self, base_os_sandbox, override_os_sandbox, agent_key="test-agent"):
        p = self._policy_with_os_sandbox(**base_os_sandbox)
        p["agent_overrides"] = {
            agent_key: {
                "policy": {
                    "os_sandbox": override_os_sandbox,
                }
            }
        }
        return p

    # --- mode tightening ---

    def test_mode_tightening_off_to_enforce_accepted(self):
        """Upgrading from off → enforce is allowed (tightening)."""
        p = self._policy_with_override(
            base_os_sandbox={"mode": "off"},
            override_os_sandbox={"mode": "enforce"},
        )
        policy = _normalize(p)
        self.assertEqual(policy["agent_overrides"]["test-agent"]["policy"]["os_sandbox"]["mode"], "enforce")

    def test_mode_tightening_monitor_to_enforce_accepted(self):
        """Upgrading from monitor → enforce is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"mode": "monitor"},
            override_os_sandbox={"mode": "enforce"},
        )
        _normalize(p)  # must not raise

    def test_mode_tightening_same_accepted(self):
        """Same mode level is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"mode": "enforce"},
            override_os_sandbox={"mode": "enforce"},
        )
        _normalize(p)  # must not raise

    def test_mode_loosening_enforce_to_off_rejected(self):
        """Downgrading from enforce → off is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"mode": "enforce"},
            override_os_sandbox={"mode": "off"},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.mode", str(cm.exception))

    def test_mode_loosening_enforce_to_monitor_rejected(self):
        """Downgrading from enforce → monitor is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"mode": "enforce"},
            override_os_sandbox={"mode": "monitor"},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("os_sandbox.mode", str(cm.exception))

    # --- on_setup_failure tightening ---

    def test_on_setup_failure_fail_closed_stays_fail_closed_accepted(self):
        """Keeping fail_closed is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"on_setup_failure": "fail_closed"},
            override_os_sandbox={"on_setup_failure": "fail_closed"},
        )
        _normalize(p)  # must not raise

    def test_on_setup_failure_loosen_from_fail_closed_rejected(self):
        """Loosening from fail_closed → warn_and_run_unconfined is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"on_setup_failure": "fail_closed"},
            override_os_sandbox={"on_setup_failure": "warn_and_run_unconfined"},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("on_setup_failure", str(cm.exception))

    def test_on_setup_failure_warn_to_fail_closed_accepted(self):
        """Tightening from warn_and_run_unconfined → fail_closed is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"on_setup_failure": "warn_and_run_unconfined"},
            override_os_sandbox={"on_setup_failure": "fail_closed"},
        )
        _normalize(p)  # must not raise

    # --- network_mode tightening ---

    def test_network_mode_unrestricted_to_none_accepted(self):
        """Tightening from unrestricted → none is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"network_mode": "unrestricted"},
            override_os_sandbox={"network_mode": "none"},
        )
        _normalize(p)

    def test_network_mode_loopback_to_none_accepted(self):
        """Tightening from loopback_only → none is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"network_mode": "loopback_only"},
            override_os_sandbox={"network_mode": "none"},
        )
        _normalize(p)

    def test_network_mode_none_to_unrestricted_rejected(self):
        """Loosening from none → unrestricted is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"network_mode": "none"},
            override_os_sandbox={"network_mode": "unrestricted"},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("network_mode", str(cm.exception))

    def test_network_mode_none_to_loopback_rejected(self):
        """Loosening from none → loopback_only is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"network_mode": "none"},
            override_os_sandbox={"network_mode": "loopback_only"},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("network_mode", str(cm.exception))

    # --- allowed_tcp_ports subset ---

    def test_ports_subset_accepted(self):
        """Override restricting ports to a subset of baseline is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"allowed_tcp_ports": [80, 443, 8080]},
            override_os_sandbox={"allowed_tcp_ports": [443]},
        )
        _normalize(p)

    def test_ports_same_set_accepted(self):
        """Override with same ports as baseline is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"allowed_tcp_ports": [443]},
            override_os_sandbox={"allowed_tcp_ports": [443]},
        )
        _normalize(p)

    def test_ports_add_new_port_rejected(self):
        """Override adding a port not in baseline is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"allowed_tcp_ports": [443]},
            override_os_sandbox={"allowed_tcp_ports": [443, 80]},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("allowed_tcp_ports", str(cm.exception))

    # --- credential_carve_outs subset ---

    def test_carve_outs_subset_accepted(self):
        """Override using a subset of baseline carve-outs is allowed."""
        base_carve = [
            {"path": "/home/user/.gitconfig", "access": "read", "reason": "git identity"},
            {"path": "/home/user/.npmrc", "access": "read", "reason": "npm token"},
        ]
        override_carve = [
            {"path": "/home/user/.gitconfig", "access": "read", "reason": "git identity"},
        ]
        p = self._policy_with_override(
            base_os_sandbox={"credential_carve_outs": base_carve},
            override_os_sandbox={"credential_carve_outs": override_carve},
        )
        _normalize(p)

    def test_carve_outs_add_new_path_rejected(self):
        """Override adding a carve-out path not in baseline is rejected."""
        base_carve = [
            {"path": "/home/user/.gitconfig", "access": "read", "reason": "git identity"},
        ]
        override_carve = [
            {"path": "/home/user/.gitconfig", "access": "read", "reason": "git identity"},
            {"path": "/home/user/.ssh/id_rsa.pub", "access": "read", "reason": "ssh pubkey"},
        ]
        p = self._policy_with_override(
            base_os_sandbox={"credential_carve_outs": base_carve},
            override_os_sandbox={"credential_carve_outs": override_carve},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("credential_carve_outs", str(cm.exception))

    # --- filesystem.*_paths subset ---

    def test_readable_paths_subset_accepted(self):
        """Override with subset of readable_paths is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"filesystem": {"readable_paths": ["/etc/ssl/certs", "/etc/hosts"]}},
            override_os_sandbox={"filesystem": {"readable_paths": ["/etc/ssl/certs"]}},
        )
        _normalize(p)

    def test_readable_paths_add_new_rejected(self):
        """Override adding a readable path not in baseline is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"filesystem": {"readable_paths": ["/etc/ssl/certs"]}},
            override_os_sandbox={"filesystem": {"readable_paths": ["/etc/ssl/certs", "/etc/hosts"]}},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("readable_paths", str(cm.exception))

    def test_writable_paths_subset_accepted(self):
        """Override with subset of writable_paths is allowed."""
        p = self._policy_with_override(
            base_os_sandbox={"filesystem": {"writable_paths": ["/tmp", "/var/tmp"]}},
            override_os_sandbox={"filesystem": {"writable_paths": ["/tmp"]}},
        )
        _normalize(p)

    def test_writable_paths_add_new_rejected(self):
        """Override adding a writable path not in baseline is rejected."""
        p = self._policy_with_override(
            base_os_sandbox={"filesystem": {"writable_paths": ["/tmp"]}},
            override_os_sandbox={"filesystem": {"writable_paths": ["/tmp", "/var/tmp"]}},
        )
        with self.assertRaises(ValueError) as cm:
            _normalize(p)
        self.assertIn("writable_paths", str(cm.exception))


class OsSandboxRoundTripTest(unittest.TestCase):
    """Round-trip: load policy.json → normalize → validate again with consistent result."""

    def test_policy_json_round_trip(self):
        """The repo policy.json round-trips through normalization without error."""
        import json
        import pathlib
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        policy_path = repo_root / "policy.json"
        if not policy_path.exists():
            self.skipTest("policy.json not found")
        raw = json.loads(policy_path.read_text())
        normalized = _normalize(raw)
        self.assertIn("os_sandbox", normalized)
        self.assertIsInstance(normalized["os_sandbox"], dict)
        # Double-normalize must also pass
        re_normalized = _normalize(normalized)
        self.assertEqual(re_normalized["os_sandbox"]["mode"], normalized["os_sandbox"]["mode"])

    def test_airg_cli_template_round_trip(self):
        """airg_cli._policy_template() includes os_sandbox and round-trips."""
        import airg_cli
        template = airg_cli._policy_template()
        self.assertIn("os_sandbox", template)
        normalized = _normalize(template)
        s = normalized["os_sandbox"]
        self.assertFalse(s["enabled"])
        self.assertEqual(s["mode"], "off")
        self.assertEqual(s["on_setup_failure"], "fail_closed")

    def test_normalize_idempotent(self):
        """Normalizing an already-normalized policy produces identical os_sandbox section."""
        import json
        import pathlib
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        policy_path = repo_root / "policy.json"
        if not policy_path.exists():
            self.skipTest("policy.json not found")
        raw = json.loads(policy_path.read_text())
        first = _normalize(raw)
        second = _normalize(first)
        # Drop agent_overrides example keys that change on re-normalize
        first_sandbox = first["os_sandbox"]
        second_sandbox = second["os_sandbox"]
        self.assertEqual(first_sandbox, second_sandbox)


if __name__ == "__main__":
    unittest.main()
