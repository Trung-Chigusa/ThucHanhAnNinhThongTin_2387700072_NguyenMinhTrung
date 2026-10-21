"""Command-line entry point for the local SAST demo."""

import argparse
from pathlib import Path

from sast_tool.ast_analyzer import ASTAnalyzer
from sast_tool.code_quality_checker import CodeQualityChecker
from sast_tool.sarif_reporter import SarifReporter
from sast_tool.security_rule_engine import SecurityRuleEngine
from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


def analyze_file(file_path, output_file="report.sarif", rules_file=None):
    path = Path(file_path)
    code = path.read_text(encoding="utf-8")
    ast_issues = ASTAnalyzer().analyze(code)
    pattern_issues = VulnPatternMatcher().match(code)
    quality_issues = CodeQualityChecker().check(path)
    engine = SecurityRuleEngine(rules_file) if rules_file else SecurityRuleEngine()
    issues = engine.evaluate(ast_issues, pattern_issues, quality_issues)
    SarifReporter().generate_report(issues, output_file, analyzed_file=path.as_posix())
    return issues


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze one Python file and write a SARIF report.")
    parser.add_argument("file", help="Python source file to analyze")
    parser.add_argument("--output", default="report.sarif", help="SARIF output path")
    parser.add_argument("--rules", help="Optional JSON rules file")
    args = parser.parse_args(argv)
    issues = analyze_file(args.file, args.output, args.rules)
    print(f"Analysis complete: {len(issues)} finding(s). Report saved to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
