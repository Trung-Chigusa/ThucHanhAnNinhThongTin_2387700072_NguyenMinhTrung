"""Security-focused complexity metrics plus optional Flake8 findings."""

import ast
import subprocess
import sys
from pathlib import Path


class CodeQualityChecker:
    def __init__(self, max_complexity=10, max_function_lines=60, max_nesting=4):
        self.max_complexity = max_complexity
        self.max_function_lines = max_function_lines
        self.max_nesting = max_nesting

    def check(self, filepath):
        path = Path(filepath)
        try:
            code = path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(path))
        except (OSError, SyntaxError):
            return []
        issues = self._metrics(tree)
        issues.extend(self._flake8(path))
        return issues

    def _metrics(self, tree):
        issues = []
        branches = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                    ast.IfExp, ast.comprehension, ast.Match, ast.match_case)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            complexity = 1 + sum(isinstance(n, branches) for n in ast.walk(node))
            if complexity > self.max_complexity:
                issues.append(self._issue("High complexity", f"Complexity {complexity} exceeds {self.max_complexity}.", node))
            length = max(getattr(node, "end_lineno", node.lineno) - node.lineno + 1, 1)
            if length > self.max_function_lines:
                issues.append(self._issue("Long function", f"Function spans {length} lines.", node))
            nesting = self._max_nesting(node)
            if nesting > self.max_nesting:
                issues.append(self._issue("Deep nesting", f"Nested control flow depth is {nesting}.", node))
        return issues

    def _max_nesting(self, node):
        controls = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)

        def walk(parent, depth):
            best = depth
            for child in ast.iter_child_nodes(parent):
                next_depth = depth + 1 if isinstance(child, controls) else depth
                best = max(best, walk(child, next_depth))
            return best

        return walk(node, 0)

    def _flake8(self, path):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "flake8", "--format=%(code)s:%(row)d:%(col)d:%(text)s", str(path)],
                capture_output=True, text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        findings = []
        for line in result.stdout.splitlines():
            parts = line.split(":", 3)
            if len(parts) != 4:
                continue
            code, row, column, message = parts
            try:
                lineno, col = int(row), max(int(column) - 1, 0)
            except ValueError:
                continue
            findings.append({
                "type": "Lint Issue", "message": f"{code}: {message}",
                "lineno": lineno, "col_offset": col,
            })
        return findings

    @staticmethod
    def _issue(kind, message, node):
        return {"type": kind, "message": message, "lineno": node.lineno, "col_offset": node.col_offset}
