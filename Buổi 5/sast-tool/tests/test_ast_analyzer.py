import unittest

from sast_tool.ast_analyzer import ASTAnalyzer


class ASTAnalyzerTests(unittest.TestCase):
    def test_detects_eval_exec_shell_and_pickle_calls(self):
        code = "import os, pickle, subprocess\neval('1')\nexec('pass')\nos.system('echo ok')\npickle.loads(b'x')\nsubprocess.run(['echo'], shell=True)"
        findings = ASTAnalyzer().analyze(code)
        self.assertEqual([item["type"] for item in findings], [
            "Use of eval", "Use of exec", "Shell command execution",
            "Unsafe deserialization", "Shell command execution",
        ])

    def test_syntax_error_is_reported_without_raising(self):
        findings = ASTAnalyzer().analyze("def broken(:\n pass")
        self.assertEqual(findings[0]["type"], "Syntax Error")
        self.assertGreaterEqual(findings[0]["lineno"], 1)

    def test_does_not_flag_shell_false(self):
        self.assertEqual(ASTAnalyzer().analyze("subprocess.run(['echo', 'ok'], shell=False)"), [])


if __name__ == "__main__":
    unittest.main()
