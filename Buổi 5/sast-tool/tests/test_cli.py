import json
import tempfile
import unittest
from pathlib import Path

from sast_tool.main import analyze_file


class CLITests(unittest.TestCase):
    def test_analyze_file_writes_findings_to_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample.py"
            report = Path(tmp) / "report.sarif"
            source.write_text("value = eval('1 + 1')\n", encoding="utf-8")
            issues = analyze_file(source, report)
            parsed = json.loads(report.read_text(encoding="utf-8"))
        self.assertTrue(any(issue["type"] == "Use of eval" for issue in issues))
        self.assertTrue(parsed["runs"][0]["results"])


if __name__ == "__main__":
    unittest.main()
