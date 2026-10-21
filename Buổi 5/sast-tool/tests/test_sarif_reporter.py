import json
import tempfile
import unittest
from pathlib import Path

from sast_tool.sarif_reporter import SarifReporter


class SarifReporterTests(unittest.TestCase):
    def test_writes_sarif_21_with_tool_rules_and_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.sarif"
            SarifReporter().generate_report([{
                "type": "Use of eval", "message": "Avoid eval", "lineno": 3,
                "col_offset": 4, "severity": "high", "ruleId": "PY-EVAL",
            }], output, "examples/demo.py")
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "PY-EVAL")
        result = run["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startColumn"], 5)


if __name__ == "__main__":
    unittest.main()
