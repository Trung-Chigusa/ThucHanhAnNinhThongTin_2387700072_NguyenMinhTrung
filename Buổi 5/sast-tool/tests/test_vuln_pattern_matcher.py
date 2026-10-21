import json
import tempfile
import unittest
from pathlib import Path

from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


class PatternMatcherTests(unittest.TestCase):
    def test_default_rules_find_pickle_and_demo_credential_assignment(self):
        code = "demo_credential = 'DEMO_ONLY_NOT_A_SECRET'\nimport pickle\n"
        issues = VulnPatternMatcher().match(code)
        self.assertEqual(len(issues), 2)
        self.assertEqual([issue["lineno"] for issue in issues], [1, 2])

    def test_custom_rule_reports_column_and_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.json"
            rules.write_text(json.dumps([{"id": "TEST", "pattern": "danger", "message": "found"}]), encoding="utf-8")
            findings = VulnPatternMatcher(rules).match("safe\n  danger()")
        self.assertEqual(findings[0]["lineno"], 2)
        self.assertEqual(findings[0]["col_offset"], 2)

    def test_invalid_regex_is_a_clear_configuration_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.json"
            rules.write_text('[{"pattern":"["}]', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid pattern"):
                VulnPatternMatcher(rules).match("anything")


if __name__ == "__main__":
    unittest.main()
