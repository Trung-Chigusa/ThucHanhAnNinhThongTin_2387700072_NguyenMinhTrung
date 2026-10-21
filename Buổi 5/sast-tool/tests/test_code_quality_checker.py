import tempfile
import unittest
from pathlib import Path

from sast_tool.code_quality_checker import CodeQualityChecker


class CodeQualityCheckerTests(unittest.TestCase):
    def test_reports_complexity_length_and_nesting(self):
        source = "def f(x):\n" + "".join(
            "    " * (level + 1) + "if x:\n" for level in range(5)
        ) + "                        return 1\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.py"
            path.write_text(source, encoding="utf-8")
            checker = CodeQualityChecker(max_complexity=2, max_function_lines=3, max_nesting=2)
            findings = checker._metrics(__import__("ast").parse(source))
        self.assertEqual({item["type"] for item in findings}, {"High complexity", "Long function", "Deep nesting"})

    def test_empty_file_has_no_metrics(self):
        self.assertEqual(CodeQualityChecker()._metrics(__import__("ast").parse("")), [])


if __name__ == "__main__":
    unittest.main()
