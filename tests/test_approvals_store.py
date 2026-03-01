import os
import pathlib
import sqlite3
import tempfile
import unittest

import approvals
import audit


class ApprovalStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = pathlib.Path(self.tmp.name) / "approvals.db"
        self.log = pathlib.Path(self.tmp.name) / "activity.log"
        self.orig_db = approvals.APPROVAL_DB_PATH
        self.orig_log = audit.LOG_PATH
        approvals.APPROVAL_DB_PATH = self.db
        audit.LOG_PATH = str(self.log)
        approvals.reset_approval_state_for_tests()

    def tearDown(self):
        approvals.APPROVAL_DB_PATH = self.orig_db
        audit.LOG_PATH = self.orig_log
        approvals.reset_approval_state_for_tests()
        self.tmp.cleanup()

    def test_issue_and_list_pending_approvals(self):
        token, _exp = approvals.issue_or_reuse_approval_token(
            "rm test.txt",
            session_id="sess-1",
            affected_paths=["/tmp/a", "/tmp/b"],
        )
        self.assertTrue(token)
        pending = approvals.list_pending_approvals()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["session_id"], "sess-1")
        self.assertEqual(pending[0]["command"], "rm test.txt")
        self.assertEqual(pending[0]["affected_paths"], ["/tmp/a", "/tmp/b"])

    def test_consume_and_deny_paths(self):
        token, _ = approvals.issue_or_reuse_approval_token("cat x.txt", session_id="sess-2")
        ok, reason, _rule = approvals.consume_command_approval("cat x.txt", token)
        self.assertTrue(ok)
        self.assertIsNone(reason)
        # Grant is one-time for the same session+command.
        self.assertTrue(approvals.consume_approved_command("sess-2", "cat x.txt"))
        self.assertFalse(approvals.consume_approved_command("sess-2", "cat x.txt"))

        token2, _ = approvals.issue_or_reuse_approval_token("cat y.txt", session_id="sess-2")
        denied, msg = approvals.deny_command_approval(token2)
        self.assertTrue(denied)
        self.assertIn("removed", msg)

    def test_approval_is_session_scoped(self):
        token, _ = approvals.issue_or_reuse_approval_token("rm tmp.txt", session_id="session-A")
        ok, _reason, _rule = approvals.consume_command_approval("rm tmp.txt", token)
        self.assertTrue(ok)
        # Different session should not consume grant.
        self.assertFalse(approvals.consume_approved_command("session-B", "rm tmp.txt"))
        self.assertTrue(approvals.consume_approved_command("session-A", "rm tmp.txt"))

    def test_tampered_approval_grant_signature_is_rejected(self):
        token, _ = approvals.issue_or_reuse_approval_token("rm tmp.txt", session_id="session-A")
        ok, _reason, _rule = approvals.consume_command_approval("rm tmp.txt", token)
        self.assertTrue(ok)

        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE approved_commands SET signature = ? WHERE session_id = ? AND command_hash = ?",
                ("tampered", "session-A", approvals._command_hash("rm tmp.txt")),
            )
            conn.commit()

        self.assertFalse(approvals.consume_approved_command("session-A", "rm tmp.txt"))

    def test_empty_hmac_key_file_is_regenerated(self):
        key_path = pathlib.Path(self.tmp.name) / "approvals.db.hmac.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text("")
        self.assertEqual(key_path.stat().st_size, 0)
        old_env = os.environ.get("AIRG_APPROVAL_HMAC_KEY_PATH")
        os.environ["AIRG_APPROVAL_HMAC_KEY_PATH"] = str(key_path)
        try:
            approvals._APPROVAL_HMAC_CACHE = None
            key = approvals._approval_signing_key()
            self.assertTrue(key)
            self.assertGreater(key_path.stat().st_size, 0)
        finally:
            if old_env is None:
                os.environ.pop("AIRG_APPROVAL_HMAC_KEY_PATH", None)
            else:
                os.environ["AIRG_APPROVAL_HMAC_KEY_PATH"] = old_env


if __name__ == "__main__":
    unittest.main()
