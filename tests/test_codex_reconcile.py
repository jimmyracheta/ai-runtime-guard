"""
Tests for src/codex_sandbox_reconcile.py (P1-c, T7).

Covers:
  * detection precedence (project overrides global when trusted) using temp
    config.toml files
  * the full reconcile decision table
  * apply_and_restore writes danger-full-access ONLY when
    outer_wall_confirmed=True, and restores the original afterward
  * refuses to weaken when the outer wall is not confirmed

All tests use TEMP config files — never the real ~/.codex.
"""

import pathlib
import sys
import tempfile
import unittest

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import codex_sandbox_reconcile as csr


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.home = self.root / "home"
        self.workspace = self.root / "home" / "proj"
        (self.home / ".codex").mkdir(parents=True)
        (self.workspace / ".codex").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_global(self, text):
        (self.home / ".codex" / "config.toml").write_text(text, encoding="utf-8")

    def _write_project(self, text):
        (self.workspace / ".codex" / "config.toml").write_text(text, encoding="utf-8")

    def test_global_only(self):
        self._write_global('sandbox_mode = "read-only"\napproval_policy = "untrusted"\n')
        d = csr.detect_codex_sandbox_mode(self.home, self.workspace)
        self.assertEqual(d["effective_sandbox_mode"], "read-only")
        self.assertEqual(d["source"], "global")

    def test_project_overrides_global_when_trusted(self):
        self._write_global(
            'sandbox_mode = "read-only"\napproval_policy = "untrusted"\n'
            f'[projects."{self.workspace}"]\ntrust_level = "trusted"\n'
        )
        self._write_project('sandbox_mode = "workspace-write"\napproval_policy = "on-request"\n')
        d = csr.detect_codex_sandbox_mode(self.home, self.workspace)
        self.assertEqual(d["effective_sandbox_mode"], "workspace-write")
        self.assertEqual(d["source"], "project")
        self.assertTrue(d["project_trusted"])

    def test_project_ignored_when_not_trusted(self):
        self._write_global('sandbox_mode = "read-only"\napproval_policy = "untrusted"\n')
        self._write_project('sandbox_mode = "danger-full-access"\n')
        d = csr.detect_codex_sandbox_mode(self.home, self.workspace)
        # untrusted project => global wins
        self.assertEqual(d["effective_sandbox_mode"], "read-only")
        self.assertEqual(d["source"], "global")
        self.assertFalse(d["project_trusted"])

    def test_absent_configs_yield_builtin_default(self):
        d = csr.detect_codex_sandbox_mode(self.home, self.workspace)
        self.assertEqual(d["effective_sandbox_mode"], csr.CODEX_BUILTIN_DEFAULT)
        self.assertEqual(d["source"], "builtin_default")

    def test_unreadable_config_flagged(self):
        # Malformed TOML -> readable=False (fail-closed signal for enforce).
        self._write_global('sandbox_mode = "read-only\n[broken')
        d = csr.detect_codex_sandbox_mode(self.home, self.workspace)
        self.assertFalse(d["readable"])

    def test_effective_path_for_write_is_project_when_trusted(self):
        self._write_global(
            'sandbox_mode = "read-only"\n'
            f'[projects."{self.workspace}"]\ntrust_level = "trusted"\n'
        )
        self._write_project('sandbox_mode = "workspace-write"\n')
        d = csr.detect_codex_sandbox_mode(self.home, self.workspace)
        self.assertEqual(
            csr.effective_config_path_for_write(d),
            self.workspace / ".codex" / "config.toml",
        )


class ReconcileDecisionTests(unittest.TestCase):
    def test_enforce_confirmed_active_codex_sets_danger(self):
        for mode in ("read-only", "workspace-write"):
            d = csr.reconcile_decision(mode, "enforce", outer_wall_confirmed=True)
            self.assertEqual(d["action"], csr.ACTION_SET_DANGER_FULL_ACCESS)
            self.assertEqual(d["write_value"], csr.DANGER_FULL_ACCESS)

    def test_enforce_not_confirmed_leaves_intact(self):
        d = csr.reconcile_decision("workspace-write", "enforce", outer_wall_confirmed=False)
        self.assertEqual(d["action"], csr.ACTION_LEAVE_INTACT)
        self.assertIsNone(d["write_value"])

    def test_enforce_codex_already_danger_is_noop(self):
        d = csr.reconcile_decision("danger-full-access", "enforce", outer_wall_confirmed=True)
        self.assertEqual(d["action"], csr.ACTION_NOOP)

    def test_enforce_unknown_codex_fails_closed(self):
        d = csr.reconcile_decision("", "enforce", outer_wall_confirmed=True)
        self.assertEqual(d["action"], csr.ACTION_FAIL_CLOSED)
        d2 = csr.reconcile_decision("bogus-mode", "enforce", outer_wall_confirmed=True)
        self.assertEqual(d2["action"], csr.ACTION_FAIL_CLOSED)

    def test_off_mode_never_modifies(self):
        d = csr.reconcile_decision("workspace-write", "off", outer_wall_confirmed=True)
        self.assertEqual(d["action"], csr.ACTION_NOOP)

    def test_monitor_mode_never_modifies(self):
        d = csr.reconcile_decision("read-only", "monitor", outer_wall_confirmed=False)
        self.assertEqual(d["action"], csr.ACTION_NOOP)


class ApplyAndRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = pathlib.Path(self.tmp.name) / "config.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_danger_only_when_confirmed_and_restores(self):
        self.cfg.write_text('sandbox_mode = "workspace-write"\napproval_policy = "on-request"\n')
        with csr.apply_and_restore(self.cfg, csr.DANGER_FULL_ACCESS, outer_wall_confirmed=True) as wrote:
            self.assertTrue(wrote)
            inside = self.cfg.read_text()
            self.assertIn('sandbox_mode = "danger-full-access"', inside)
            # other keys preserved
            self.assertIn('approval_policy = "on-request"', inside)
        # restored
        after = self.cfg.read_text()
        self.assertIn('sandbox_mode = "workspace-write"', after)
        self.assertNotIn("danger-full-access", after)

    def test_refuses_to_weaken_when_wall_not_confirmed(self):
        original = 'sandbox_mode = "workspace-write"\n'
        self.cfg.write_text(original)
        with csr.apply_and_restore(self.cfg, csr.DANGER_FULL_ACCESS, outer_wall_confirmed=False) as wrote:
            self.assertFalse(wrote)
            # file untouched DURING the context
            self.assertEqual(self.cfg.read_text(), original)
        # still untouched
        self.assertEqual(self.cfg.read_text(), original)

    def test_restores_by_removing_key_if_absent_originally(self):
        self.cfg.write_text('approval_policy = "on-request"\n')
        with csr.apply_and_restore(self.cfg, csr.DANGER_FULL_ACCESS, outer_wall_confirmed=True) as wrote:
            self.assertTrue(wrote)
            self.assertIn("danger-full-access", self.cfg.read_text())
        after = self.cfg.read_text()
        self.assertNotIn("sandbox_mode", after)
        self.assertIn('approval_policy = "on-request"', after)

    def test_removes_file_if_it_did_not_exist(self):
        self.assertFalse(self.cfg.exists())
        with csr.apply_and_restore(self.cfg, csr.DANGER_FULL_ACCESS, outer_wall_confirmed=True) as wrote:
            self.assertTrue(wrote)
            self.assertTrue(self.cfg.exists())
        self.assertFalse(self.cfg.exists())

    def test_restores_on_exception(self):
        self.cfg.write_text('sandbox_mode = "read-only"\n')
        with self.assertRaises(RuntimeError):
            with csr.apply_and_restore(self.cfg, csr.DANGER_FULL_ACCESS, outer_wall_confirmed=True):
                self.assertIn("danger-full-access", self.cfg.read_text())
                raise RuntimeError("boom")
        self.assertIn('sandbox_mode = "read-only"', self.cfg.read_text())
        self.assertNotIn("danger-full-access", self.cfg.read_text())

    def test_rejects_invalid_write_value(self):
        self.cfg.write_text('sandbox_mode = "read-only"\n')
        with self.assertRaises(ValueError):
            with csr.apply_and_restore(self.cfg, "bogus", outer_wall_confirmed=True):
                pass

    def test_does_not_disturb_subtable_sandbox_mode(self):
        # A sandbox_mode inside a sub-table must not be treated as top-level.
        text = (
            'sandbox_mode = "workspace-write"\n'
            "[sandbox_workspace_write]\n"
            "network_access = false\n"
        )
        self.cfg.write_text(text)
        with csr.apply_and_restore(self.cfg, csr.DANGER_FULL_ACCESS, outer_wall_confirmed=True):
            inside = self.cfg.read_text()
            self.assertIn('sandbox_mode = "danger-full-access"', inside)
            self.assertIn("network_access = false", inside)
        self.assertEqual(self.cfg.read_text(), text)


if __name__ == "__main__":
    unittest.main()
