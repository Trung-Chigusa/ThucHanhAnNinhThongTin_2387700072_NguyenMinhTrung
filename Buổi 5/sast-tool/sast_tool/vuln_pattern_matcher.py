"""Configurable regular-expression checks for source-code smells."""

import json
import re
from pathlib import Path


DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "default_rules.json"


class VulnPatternMatcher:
    def __init__(self, rules_file=DEFAULT_RULES):
        self.rules_file = Path(rules_file)

    def match(self, code: str):
        try:
            rules = json.loads(self.rules_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot load pattern rules: {exc}") from exc
        if not isinstance(rules, list):
            raise ValueError("Pattern rules must be a JSON array")

        issues = []
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str):
                continue
            try:
                pattern = re.compile(rule["pattern"], re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Invalid pattern {rule.get('id', '<unnamed>')}: {exc}") from exc
            for match in pattern.finditer(code):
                line = code.count("\n", 0, match.start()) + 1
                line_start = code.rfind("\n", 0, match.start()) + 1
                issues.append({
                    "type": rule.get("type", "Pattern Match"),
                    "message": rule.get("message", "Source matched a configured rule."),
                    "lineno": line,
                    "col_offset": match.start() - line_start,
                    "ruleId": rule.get("id"),
                })
        return issues
