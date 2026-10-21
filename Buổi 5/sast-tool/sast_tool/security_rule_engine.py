"""Apply configurable severities and stable identifiers to findings."""

import json
from pathlib import Path


DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "default_rules.json"


class SecurityRuleEngine:
    def __init__(self, rules_file=DEFAULT_RULES):
        try:
            self.rules = json.loads(Path(rules_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot load security rules: {exc}") from exc
        if not isinstance(self.rules, list):
            raise ValueError("Security rules must be a JSON array")

    def evaluate(self, *issue_groups):
        by_type = {rule["type"]: rule for rule in self.rules if isinstance(rule, dict) and "type" in rule}
        output = []
        for group in issue_groups:
            for original in group:
                issue = dict(original)
                rule = by_type.get(issue.get("type"), {})
                issue["ruleId"] = issue.get("ruleId") or rule.get("id") or "PY-GENERAL"
                issue["severity"] = issue.get("severity") or rule.get("severity", "medium")
                output.append(issue)
        return output
