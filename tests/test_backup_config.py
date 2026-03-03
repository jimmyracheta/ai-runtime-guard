import os
import pathlib
import unittest
from unittest.mock import patch

import config


class BackupConfigTests(unittest.TestCase):
    def test_default_backup_root_uses_state_dir(self) -> None:
        with patch.dict(os.environ, {"AIRG_BACKUP_ROOT": ""}, clear=False):
            expected = (config._default_base_state_dir() / "backups").resolve()
            self.assertEqual(config._default_backup_root(), expected)

    def test_default_backup_root_honors_env_override(self) -> None:
        override = pathlib.Path("/tmp/airg-custom-backups").resolve()
        with patch.dict(os.environ, {"AIRG_BACKUP_ROOT": str(override)}, clear=False):
            self.assertEqual(config._default_backup_root(), override)

    def test_policy_normalization_defaults_backup_root_to_runtime_state(self) -> None:
        policy = config._validate_and_normalize_policy({})
        self.assertEqual(policy["audit"]["backup_root"], str(config._default_backup_root()))


if __name__ == "__main__":
    unittest.main()
