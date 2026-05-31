"""
Tests for src/sandbox_launcher.py (P1-c).

Pure command-construction + decision-logic tests. No real sandboxing happens
here (real Landlock/namespace confinement is verified by the operator on Linux).
Covers:
  * select_launcher across mocked probe results
  * landrun argv correctness (workspace rw, socket carve-in, HOME, no creds,
    no shell metacharacters / shell=True)
  * bwrap argv correctness (workspace bind rw, --unshare-net when net off,
    socket bind present)
  * env hygiene (HOME=workspace, AIRG_SOCKET_PATH, dangerous vars dropped)
  * fail-closed vs explicit unconfined opt-out
"""

import pathlib
import sys
import unittest

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import sandbox_launcher as sl


def _probe(*, landlock_abi=None, userns="no", bwrap=False, landrun=False):
    return {
        "landlock": {"available": landlock_abi is not None, "abi_version": landlock_abi},
        "userns": {"verdict": userns},
        "launchers": {
            "bwrap": {"found": bwrap},
            "landrun": {"found": landrun},
        },
    }


WS = "/home/user/myproject"
SOCK = "/home/user/.local/state/airg/sockets/codex.sock"
AGENT = ["codex", "exec", "--full-auto"]


class SelectLauncherTests(unittest.TestCase):
    def test_landlock_only_host_selects_landrun(self):
        probe = _probe(landlock_abi=4, userns="no", landrun=True, bwrap=False)
        self.assertEqual(sl.select_launcher(probe, {"launcher": "auto"}), "landrun")

    def test_userns_only_host_selects_bwrap(self):
        probe = _probe(landlock_abi=None, userns="yes", bwrap=True, landrun=False)
        self.assertEqual(sl.select_launcher(probe, {"launcher": "auto"}), "bwrap")

    def test_both_available_prefers_bwrap_in_auto(self):
        probe = _probe(landlock_abi=4, userns="yes", bwrap=True, landrun=True)
        self.assertEqual(sl.select_launcher(probe, {"launcher": "auto"}), "bwrap")

    def test_neither_returns_none(self):
        probe = _probe(landlock_abi=None, userns="no", bwrap=False, landrun=False)
        self.assertIsNone(sl.select_launcher(probe, {"launcher": "auto"}))

    def test_apparmor_restricted_userns_not_usable_for_bwrap(self):
        probe = _probe(landlock_abi=None, userns="yes_but_apparmor_restricted", bwrap=True)
        self.assertIsNone(sl.select_launcher(probe, {"launcher": "auto"}))

    def test_explicit_landrun_preference_honored(self):
        probe = _probe(landlock_abi=1, userns="yes", bwrap=True, landrun=True)
        self.assertEqual(sl.select_launcher(probe, {"launcher": "landrun"}), "landrun")

    def test_explicit_bwrap_preference_unavailable_returns_none(self):
        probe = _probe(landlock_abi=4, userns="no", bwrap=False, landrun=True)
        self.assertIsNone(sl.select_launcher(probe, {"launcher": "bwrap"}))

    def test_landrun_requires_binary_present(self):
        probe = _probe(landlock_abi=4, userns="no", landrun=False)
        self.assertIsNone(sl.select_launcher(probe, {"launcher": "auto"}))


def _spec(**overrides):
    base = dict(
        workspace_root=WS,
        bridge_socket_path=SOCK,
        agent_argv=list(AGENT),
        read_exec_paths=["/usr/bin", "/usr/lib"],
        readable_paths=["/etc/ssl/certs", "/etc/passwd"],
        writable_paths=["/tmp"],
        network_mode="none",
    )
    base.update(overrides)
    return sl.LauncherSpec(**base)


class LandrunArgvTests(unittest.TestCase):
    def test_is_a_list_of_strings(self):
        argv = sl.build_landrun_argv(_spec())
        self.assertIsInstance(argv, list)
        self.assertTrue(all(isinstance(t, str) for t in argv))
        self.assertEqual(argv[0], "landrun")

    def test_workspace_rw_present(self):
        argv = sl.build_landrun_argv(_spec())
        # workspace is granted read/write/exec
        idx = argv.index("--rwx")
        self.assertEqual(argv[idx + 1], WS)

    def test_socket_carved_rw(self):
        argv = sl.build_landrun_argv(_spec())
        # socket appears as a --rw target
        rw_targets = [argv[i + 1] for i, t in enumerate(argv) if t == "--rw"]
        self.assertIn(SOCK, rw_targets)

    def test_home_set_to_workspace(self):
        argv = sl.build_landrun_argv(_spec())
        self.assertIn(f"HOME={WS}", argv)

    def test_socket_env_advertised(self):
        argv = sl.build_landrun_argv(_spec())
        self.assertIn(f"AIRG_SOCKET_PATH={SOCK}", argv)

    def test_credential_path_not_granted(self):
        # No credential carve-out => ~/.ssh must NOT appear anywhere in argv.
        argv = sl.build_landrun_argv(_spec())
        joined = " ".join(argv)
        self.assertNotIn("/.ssh", joined)
        self.assertNotIn("/.aws", joined)
        self.assertNotIn("/.npmrc", joined)

    def test_no_shell_metacharacters_or_interpolation(self):
        # The agent command is passed as discrete tokens; nothing is a shell
        # string. There must be no element that is itself a compound shell line.
        argv = sl.build_landrun_argv(_spec())
        for tok in argv:
            self.assertNotIn(";", tok)
            self.assertNotIn("&&", tok)
            self.assertNotIn("|", tok)
        # agent tokens survive verbatim after the -- separator
        sep = argv.index("--")
        self.assertEqual(argv[sep + 1:], AGENT)

    def test_credential_carve_out_when_explicit(self):
        spec = _spec(credential_carve_outs=[{"path": "/home/user/.gitconfig", "access": "read", "reason": "x"}])
        argv = sl.build_landrun_argv(spec)
        ro_targets = [argv[i + 1] for i, t in enumerate(argv) if t == "--ro"]
        self.assertIn("/home/user/.gitconfig", ro_targets)

    def test_missing_socket_raises(self):
        with self.assertRaises(ValueError):
            sl.build_landrun_argv(_spec(bridge_socket_path=""))


class BwrapArgvTests(unittest.TestCase):
    def test_is_a_list_starting_with_bwrap(self):
        argv = sl.build_bwrap_argv(_spec())
        self.assertEqual(argv[0], "bwrap")
        self.assertTrue(all(isinstance(t, str) for t in argv))

    def test_workspace_bind_rw(self):
        argv = sl.build_bwrap_argv(_spec())
        # --bind WS WS  (rw bind)
        for i, t in enumerate(argv):
            if t == "--bind" and argv[i + 1] == WS and argv[i + 2] == WS:
                break
        else:
            self.fail("workspace rw --bind not found")

    def test_unshare_net_when_network_off(self):
        argv = sl.build_bwrap_argv(_spec(network_mode="none"))
        self.assertIn("--unshare-net", argv)

    def test_share_net_when_unrestricted(self):
        argv = sl.build_bwrap_argv(_spec(network_mode="unrestricted"))
        self.assertIn("--share-net", argv)
        self.assertNotIn("--unshare-net", argv)

    def test_socket_bind_present(self):
        argv = sl.build_bwrap_argv(_spec())
        for i, t in enumerate(argv):
            if t == "--bind" and argv[i + 1] == SOCK and argv[i + 2] == SOCK:
                break
        else:
            self.fail("socket --bind carve-in not found")

    def test_home_setenv(self):
        argv = sl.build_bwrap_argv(_spec())
        for i, t in enumerate(argv):
            if t == "--setenv" and argv[i + 1] == "HOME" and argv[i + 2] == WS:
                break
        else:
            self.fail("HOME setenv to workspace not found")

    def test_private_tmpfs_for_tmp(self):
        argv = sl.build_bwrap_argv(_spec(writable_paths=["/tmp"]))
        self.assertIn("--tmpfs", argv)

    def test_agent_argv_verbatim_after_separator(self):
        argv = sl.build_bwrap_argv(_spec())
        sep = argv.index("--")
        self.assertEqual(argv[sep + 1:], AGENT)

    def test_no_credential_paths(self):
        argv = sl.build_bwrap_argv(_spec())
        joined = " ".join(argv)
        self.assertNotIn("/.ssh", joined)
        self.assertNotIn("/.aws", joined)


class EnvHygieneTests(unittest.TestCase):
    def test_home_and_socket_set(self):
        env = sl.build_agent_env(WS, SOCK, source_env={})
        self.assertEqual(env["HOME"], WS)
        self.assertEqual(env["AIRG_SOCKET_PATH"], SOCK)

    def test_dangerous_vars_dropped(self):
        src = {
            "LD_PRELOAD": "/evil.so",
            "PYTHONPATH": "/evil",
            "GIT_SSH_COMMAND": "ssh -o x",
            "DYLD_INSERT_LIBRARIES": "/evil.dylib",
            "PATH": "/usr/bin",
        }
        env = sl.build_agent_env(WS, SOCK, source_env=src)
        for bad in ("LD_PRELOAD", "PYTHONPATH", "GIT_SSH_COMMAND", "DYLD_INSERT_LIBRARIES"):
            self.assertNotIn(bad, env)
        self.assertEqual(env["PATH"], "/usr/bin")

    def test_secret_like_vars_dropped(self):
        src = {"OPENAI_API_KEY": "sk-x", "MY_TOKEN": "t", "DB_PASSWORD": "p", "GH_SECRET": "s"}
        env = sl.build_agent_env(WS, SOCK, source_env=src)
        for bad in src:
            self.assertNotIn(bad, env)

    def test_airg_prefix_preserved(self):
        src = {"AIRG_AGENT_ID": "codex-1", "AIRG_WORKSPACE": WS}
        env = sl.build_agent_env(WS, SOCK, source_env=src)
        self.assertEqual(env["AIRG_AGENT_ID"], "codex-1")

    def test_defaults_filled(self):
        env = sl.build_agent_env(WS, SOCK, source_env={})
        self.assertIn("PATH", env)
        self.assertIn("LANG", env)
        self.assertEqual(env["LC_ALL"], env["LANG"])


class EstablishAndLaunchTests(unittest.TestCase):
    def test_mode_off_runs_bare(self):
        plan = sl.establish_and_launch(
            os_sandbox_cfg={"mode": "off"},
            probe_result=_probe(),
            workspace_root=WS,
            socket_path=SOCK,
            agent_argv=AGENT,
            source_env={},
        )
        self.assertFalse(plan.confined)
        self.assertEqual(plan.sandbox_argv, AGENT)
        self.assertEqual(plan.env["HOME"], WS)

    def test_enforce_no_launcher_fail_closed_raises(self):
        with self.assertRaises(sl.SandboxSetupError):
            sl.establish_and_launch(
                os_sandbox_cfg={"mode": "enforce", "on_setup_failure": "fail_closed"},
                probe_result=_probe(landlock_abi=None, userns="no"),
                workspace_root=WS,
                socket_path=SOCK,
                agent_argv=AGENT,
                source_env={},
            )

    def test_enforce_no_launcher_optout_runs_unconfined_with_warning(self):
        plan = sl.establish_and_launch(
            os_sandbox_cfg={"mode": "enforce", "on_setup_failure": "warn_and_run_unconfined"},
            probe_result=_probe(landlock_abi=None, userns="no"),
            workspace_root=WS,
            socket_path=SOCK,
            agent_argv=AGENT,
            source_env={},
        )
        self.assertFalse(plan.confined)
        self.assertTrue(plan.unconfined_optout)
        self.assertEqual(plan.sandbox_argv, AGENT)
        self.assertTrue(any("WARN" in line for line in plan.decision_log))

    def test_enforce_with_landrun_builds_wrapped_argv(self):
        plan = sl.establish_and_launch(
            os_sandbox_cfg={"mode": "enforce"},
            probe_result=_probe(landlock_abi=4, userns="no", landrun=True),
            workspace_root=WS,
            socket_path=SOCK,
            agent_argv=AGENT,
            source_env={},
        )
        self.assertTrue(plan.confined)
        self.assertEqual(plan.launcher, "landrun")
        self.assertEqual(plan.sandbox_argv[0], "landrun")
        self.assertIn(SOCK, plan.sandbox_argv)

    def test_enforce_with_bwrap_builds_wrapped_argv(self):
        plan = sl.establish_and_launch(
            os_sandbox_cfg={"mode": "enforce"},
            probe_result=_probe(landlock_abi=None, userns="yes", bwrap=True),
            workspace_root=WS,
            socket_path=SOCK,
            agent_argv=AGENT,
            source_env={},
        )
        self.assertTrue(plan.confined)
        self.assertEqual(plan.launcher, "bwrap")
        self.assertEqual(plan.sandbox_argv[0], "bwrap")

    def test_monitor_runs_unconfined(self):
        plan = sl.establish_and_launch(
            os_sandbox_cfg={"mode": "monitor"},
            probe_result=_probe(landlock_abi=4, userns="no", landrun=True),
            workspace_root=WS,
            socket_path=SOCK,
            agent_argv=AGENT,
            source_env={},
        )
        self.assertFalse(plan.confined)
        self.assertEqual(plan.sandbox_argv, AGENT)


class CarveoutBaselineTests(unittest.TestCase):
    def test_baseline_has_both_tiers(self):
        self.assertIn("minimal", sl.CARVEOUT_BASELINE)
        self.assertIn("comfortable", sl.CARVEOUT_BASELINE)

    def test_baseline_does_not_grant_credentials(self):
        for tier in sl.CARVEOUT_BASELINE.values():
            allgranted = tier["read_exec_paths"] + tier["readable_paths"] + tier["writable_paths"]
            for p in allgranted:
                self.assertNotIn(".ssh", p)
                self.assertNotIn(".aws", p)

    def test_spec_resolves_from_baseline_when_no_filesystem_override(self):
        spec = sl.build_spec({"tier": "minimal"}, WS, SOCK, AGENT)
        self.assertEqual(spec.read_exec_paths, sl.CARVEOUT_BASELINE["minimal"]["read_exec_paths"])

    def test_filesystem_override_wins_over_baseline(self):
        cfg = {"filesystem": {"read_exec_paths": ["/custom/bin"]}}
        spec = sl.build_spec(cfg, WS, SOCK, AGENT)
        self.assertEqual(spec.read_exec_paths, ["/custom/bin"])


if __name__ == "__main__":
    unittest.main()
