import datetime
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import reports
import telemetry


class TelemetryTests(unittest.TestCase):
    def test_bucket_boundaries(self) -> None:
        cases = {
            0: "0",
            1: "1",
            2: "2-5",
            5: "2-5",
            6: "6-10",
            10: "6-10",
            11: "11-50",
            50: "11-50",
            51: "51-100",
            100: "51-100",
            101: "101-1000",
            1000: "101-1000",
            1001: "1000+",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(telemetry.bucket(value), expected)

    def test_platform_mapping(self) -> None:
        self.assertEqual(telemetry._platform_string("Darwin"), "macos")
        self.assertEqual(telemetry._platform_string("Linux"), "linux")
        self.assertEqual(telemetry._platform_string("Windows"), "windows")
        self.assertEqual(telemetry._platform_string("Plan9"), "unknown")

    def test_version_sanitization(self) -> None:
        self.assertEqual(telemetry._sanitize_version("2.1.1", max_len=32), "2.1.1")
        self.assertEqual(telemetry._sanitize_version("v2.1.1🔥", max_len=32), "v2.1.1")
        self.assertEqual(telemetry._sanitize_version("!!!!", max_len=32), "unknown")

    def test_agent_type_mapping_dedup_sort_and_cap(self) -> None:
        raw = ["cursor", "claude_desktop", "custom", "codex", "cursor", "madeup"]
        mapped = telemetry.normalize_agent_types(raw)
        self.assertEqual(mapped, ["claude_code", "codex", "cursor", "other"])

        many = [f"custom-{idx}" for idx in range(32)]
        capped = telemetry.normalize_agent_types(many)
        self.assertLessEqual(len(capped), 16)
        self.assertEqual(capped, ["other"])

    def test_payload_validation_catches_invalid_shapes(self) -> None:
        valid = {
            "airg_version": "2.1.1",
            "platform": "linux",
            "python_version": "3.12.3",
            "install_method": "unknown",
            "agents_bucket": "1",
            "agent_types": ["cursor"],
            "events_bucket": "0",
            "blocked_bucket": "0",
            "approvals_bucket": "0",
            "sentinel_enabled": True,
            "sentinel_flagged_bucket": "0",
            "sentinel_blocked_bucket": "0",
            "period_days": 1,
        }
        telemetry.validate_payload(valid)

        for key, bad_value in [
            ("platform", "mac"),
            ("install_method", "default"),
            ("agents_bucket", "7"),
            ("agent_types", ["cursor", "invalid"]),
            ("sentinel_enabled", "yes"),
            ("period_days", 0),
            ("airg_version", "x" * 33),
            ("python_version", "3.12.3/rc"),
        ]:
            with self.subTest(key=key):
                invalid = dict(valid)
                invalid[key] = bad_value
                with self.assertRaises(ValueError):
                    telemetry.validate_payload(invalid)

    def test_generator_writes_daily_payload_and_stands_down_same_day(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            policy_path = base / "policy.json"
            reports_db = base / "reports.db"
            approval_db = base / "approvals.db"
            log_path = base / "activity.log"
            reports.init_reports_store(reports_db)
            log_path.write_text("")

            policy_path.write_text(
                json.dumps(
                    {
                        "telemetry": {"enabled": True, "endpoint": telemetry.DEFAULT_ENDPOINT},
                        "reports": {"enabled": True},
                        "script_sentinel": {"enabled": True},
                    }
                )
            )

            now = datetime.datetime(2026, 4, 28, 12, 0, 0, tzinfo=datetime.UTC)
            generated = telemetry.run_generator_once(
                policy_path=policy_path,
                reports_db_path=reports_db,
                approval_db_path=approval_db,
                log_path=log_path,
                now=now,
            )
            self.assertEqual(generated.get("status"), "generated")

            payload_path = approval_db.parent / telemetry.OUTBOX_DIR_NAME / "telemetry-2026-04-28.json"
            self.assertTrue(payload_path.exists())
            updated = json.loads(policy_path.read_text())
            self.assertEqual(updated.get("telemetry", {}).get("last_payload_generated_date"), "2026-04-28")

            same_day = telemetry.run_generator_once(
                policy_path=policy_path,
                reports_db_path=reports_db,
                approval_db_path=approval_db,
                log_path=log_path,
                now=now,
            )
            self.assertEqual(same_day.get("status"), "stand_down_same_day")

    def test_uploader_stands_down_or_uploads_and_updates_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            policy_path = base / "policy.json"
            approval_db = base / "approvals.db"
            log_path = base / "activity.log"
            log_path.write_text("")
            policy_path.write_text(
                json.dumps(
                    {
                        "telemetry": {"enabled": True, "endpoint": telemetry.DEFAULT_ENDPOINT},
                        "reports": {"enabled": True},
                        "script_sentinel": {"enabled": True},
                    }
                )
            )

            empty_result = telemetry.run_uploader_once(
                policy_path=policy_path,
                approval_db_path=approval_db,
                log_path=log_path,
                now=datetime.datetime(2026, 4, 28, 12, 0, 0, tzinfo=datetime.UTC),
            )
            self.assertEqual(empty_result.get("status"), "stand_down_empty")

            out_dir = approval_db.parent / telemetry.OUTBOX_DIR_NAME
            out_dir.mkdir(parents=True, exist_ok=True)
            payload_path = out_dir / "telemetry-2026-04-28.json"
            payload_path.write_text(
                json.dumps(
                    {
                        "airg_version": "2.2.2",
                        "platform": "macos",
                        "python_version": "3.14.3",
                        "install_method": "unknown",
                        "agents_bucket": "0",
                        "agent_types": ["cursor"],
                        "events_bucket": "0",
                        "blocked_bucket": "0",
                        "approvals_bucket": "0",
                        "sentinel_enabled": True,
                        "sentinel_flagged_bucket": "0",
                        "sentinel_blocked_bucket": "0",
                        "period_days": 1,
                    }
                )
            )
            with patch.object(telemetry, "_send_once", return_value=204):
                uploaded = telemetry.run_uploader_once(
                    policy_path=policy_path,
                    approval_db_path=approval_db,
                    log_path=log_path,
                    now=datetime.datetime(2026, 4, 28, 13, 0, 0, tzinfo=datetime.UTC),
                )
            self.assertEqual(uploaded.get("status"), "uploaded")
            self.assertFalse(payload_path.exists())
            updated = json.loads(policy_path.read_text())
            telemetry_cfg = updated.get("telemetry", {})
            self.assertEqual(telemetry_cfg.get("last_sent_date"), "2026-04-28")
            self.assertTrue(str(telemetry_cfg.get("last_payload_uploaded_at", "")).endswith("Z"))

    def test_send_once_sets_user_agent_header(self) -> None:
        captured: dict[str, str] = {}

        class _Response:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        def _fake_urlopen(request, timeout=0):
            captured["user_agent"] = request.get_header("User-agent")
            captured["content_type"] = request.get_header("Content-type")
            captured["accept"] = request.get_header("Accept")
            captured["timeout"] = str(timeout)
            return _Response()

        payload = {
            "airg_version": "2.2.2",
            "platform": "macos",
            "python_version": "3.14.3",
            "install_method": "unknown",
            "agents_bucket": "0",
            "agent_types": ["cursor"],
            "events_bucket": "0",
            "blocked_bucket": "0",
            "approvals_bucket": "0",
            "sentinel_enabled": True,
            "sentinel_flagged_bucket": "0",
            "sentinel_blocked_bucket": "0",
            "period_days": 1,
        }

        with patch.object(telemetry.urllib.request, "urlopen", _fake_urlopen):
            status = telemetry._send_once("https://example.test/v1/telemetry", payload, 8)

        self.assertEqual(status, 204)
        self.assertEqual(captured["user_agent"], "ai-runtime-guard/2.2.2")
        self.assertEqual(captured["content_type"], "application/json")
        self.assertEqual(captured["accept"], "application/json")
        self.assertEqual(captured["timeout"], "8")
