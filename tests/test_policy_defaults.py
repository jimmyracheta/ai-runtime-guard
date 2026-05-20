import json
import pathlib
import unittest

import airg_cli


class PolicyDefaultTests(unittest.TestCase):
    def test_default_sensitive_paths_include_common_credential_stores(self):
        expected = {
            ".env",
            ".ssh",
            ".aws",
            ".azure",
            ".config/gcloud",
            ".docker/config.json",
            ".kube",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "/etc/passwd",
            "activity.log",
            "approvals.db",
            "approvals.db.hmac.key",
        }
        repo_policy = json.loads(pathlib.Path("policy.json").read_text())
        repo_paths = set(repo_policy.get("blocked", {}).get("paths", []))
        template_paths = set(airg_cli._policy_template().get("blocked", {}).get("paths", []))

        self.assertTrue(expected.issubset(repo_paths))
        self.assertTrue(expected.issubset(template_paths))


if __name__ == "__main__":
    unittest.main()
