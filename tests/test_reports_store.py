import json
import pathlib
import tempfile
import unittest

import reports


class ReportsStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.log_path = self.base / "activity.log"
        self.db_path = self.base / "reports.db"

    def tearDown(self):
        self.tmp.cleanup()

    def _append_event(self, payload: dict) -> None:
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")

    def test_sync_and_query(self):
        self._append_event(
            {
                "timestamp": "2026-03-01T10:00:00Z",
                "source": "ai-agent",
                "agent_id": "claude-code",
                "session_id": "s1",
                "tool": "execute_command",
                "policy_decision": "blocked",
                "decision_tier": "requires_confirmation",
                "matched_rule": "rm",
                "command": "rm x.tmp",
            }
        )
        self._append_event(
            {
                "timestamp": "2026-03-01T10:01:00Z",
                "source": "mcp-server",
                "agent_id": "claude-code",
                "session_id": "s1",
                "tool": "execute_command",
                "event": "backup_created",
                "policy_decision": "allowed",
                "decision_tier": "allowed",
                "path": "/tmp/x.tmp",
            }
        )

        sync = reports.sync_from_log(db_path=self.db_path, log_path=self.log_path, policy_reports={"enabled": True})
        self.assertTrue(sync["enabled"])

        status = reports.get_status(self.db_path)
        self.assertEqual(status["row_count"], 2)

        overview = reports.get_overview(self.db_path)
        self.assertEqual(overview["totals"]["total_events"], 2)
        self.assertEqual(overview["totals"]["blocked_events"], 1)
        self.assertEqual(overview["totals"]["backup_events"], 1)
        self.assertEqual(overview["blocked_by_rule"][0]["matched_rule"], "rm")

        filtered = reports.list_events(self.db_path, filters={"agent_id": "claude-code"}, limit=10, offset=0)
        self.assertEqual(filtered["total"], 2)

    def test_truncation_resets_offset(self):
        self._append_event(
            {
                "timestamp": "2026-03-01T10:00:00Z",
                "source": "ai-agent",
                "tool": "read_file",
                "policy_decision": "allowed",
                "decision_tier": "allowed",
                "path": "/tmp/a",
            }
        )
        reports.sync_from_log(db_path=self.db_path, log_path=self.log_path, policy_reports={"enabled": True})
        self.log_path.write_text("")
        self._append_event(
            {
                "timestamp": "2026-03-01T10:02:00Z",
                "source": "ai-agent",
                "tool": "read_file",
                "policy_decision": "allowed",
                "decision_tier": "allowed",
                "path": "/tmp/b",
            }
        )
        reports.sync_from_log(db_path=self.db_path, log_path=self.log_path, policy_reports={"enabled": True})
        status = reports.get_status(self.db_path)
        self.assertGreaterEqual(status["row_count"], 2)


if __name__ == "__main__":
    unittest.main()
