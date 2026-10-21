import json
import tempfile
import unittest
from pathlib import Path

from sast_tool.security_rule_engine import SecurityRuleEngine


class RuleEngineTests(unittest.TestCase):
    def test_applies_severity_and_rule_id_without_mutating_input(self):
        issue = {"type": "Use of eval", "message": "avoid", "lineno": 1}
        result = SecurityRuleEngine().evaluate([issue])
        self.assertEqual(result[0]["severity"], "high")
        self.assertEqual(result[0]["ruleId"], "PY-EVAL")
        self.assertNotIn("severity", issue)

    def test_rejects_non_array_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON array"):
                SecurityRuleEngine(path)


if __name__ == "__main__":
    unittest.main()
