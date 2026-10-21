"""Serialize findings to SARIF 2.1.0 for a SARIF viewer."""

import jsonpickle


class SarifReporter:
    def generate_report(self, issues, output_file="report.sarif", analyzed_file="input.py"):
        rules = {}
        results = []
        for issue in issues:
            rule_id = issue.get("ruleId", "PY-GENERAL")
            rules.setdefault(rule_id, {"id": rule_id, "name": issue.get("type", "Finding"),
                                       "shortDescription": {"text": issue.get("type", "Finding")}})
            result = {
                "ruleId": rule_id,
                "level": self._level(issue.get("severity", "medium")),
                "message": {"text": issue.get("message", "")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": str(analyzed_file).replace("\\", "/")},
                    "region": {"startLine": max(int(issue.get("lineno", 1)), 1),
                               "startColumn": max(int(issue.get("col_offset", 0)), 0) + 1},
                }}],
            }
            results.append(result)
        document = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "PySAST", "version": "1.0.0",
                                     "informationUri": "https://github.com/",
                                     "rules": list(rules.values())}},
                "results": results,
            }],
        }
        with open(output_file, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(jsonpickle.encode(document, unpicklable=False, indent=2))
            stream.write("\n")
        return document

    @staticmethod
    def _level(severity):
        return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(
            str(severity).lower(), "warning"
        )
