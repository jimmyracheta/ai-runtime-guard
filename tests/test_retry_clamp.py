import tempfile
import pathlib
import unittest

import policy_engine

from tests.test_helpers import apply_test_environment, reset_runtime_state


class RetryClampTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = pathlib.Path(self.tmp.name)
        self.env_stack = apply_test_environment(self.workspace, max_retries=3)
        self.env_stack.__enter__()
        reset_runtime_state()

    def tearDown(self):
        reset_runtime_state()
        self.env_stack.close()
        self.tmp.cleanup()

    def test_server_retry_counter_clamps_at_max_retries(self):
        counts = [
            policy_engine.register_retry(
                "rm *.tmp",
                "requires_simulation",
                "requires_simulation.bulk_file_threshold",
            )
            for _ in range(5)
        ]
        key = policy_engine.retry_key(
            "rm *.tmp",
            "requires_simulation",
            "requires_simulation.bulk_file_threshold",
        )

        self.assertEqual(counts, [1, 2, 3, 3, 3])
        self.assertEqual(max(counts), 3)
        self.assertEqual(policy_engine.SERVER_RETRY_COUNTS[key], 3)


if __name__ == "__main__":
    unittest.main()
