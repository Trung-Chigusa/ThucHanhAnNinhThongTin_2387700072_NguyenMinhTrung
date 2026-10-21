"""AST-based checks for common risky Python operations."""

import ast


class ASTAnalyzer(ast.NodeVisitor):
    _DANGEROUS_NAMES = {
        "eval": ("Use of eval", "Evaluates text as Python code."),
        "exec": ("Use of exec", "Executes text as Python code."),
    }

    def __init__(self):
        self.issues = []

    def analyze(self, code: str):
        self.issues = []
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return [{
                "type": "Syntax Error",
                "message": exc.msg,
                "lineno": exc.lineno or 1,
                "col_offset": max((exc.offset or 1) - 1, 0),
                "severity": "error",
            }]
        self.visit(tree)
        return list(self.issues)

    def visit_Call(self, node):
        name = self._call_name(node.func)
        if name in self._DANGEROUS_NAMES:
            kind, message = self._DANGEROUS_NAMES[name]
            self._add(kind, message, node)
        elif name in {"os.system", "os.popen"}:
            self._add("Shell command execution", "Shell command APIs need strict input validation.", node)
        elif name in {"pickle.load", "pickle.loads", "yaml.load"}:
            self._add("Unsafe deserialization", "Deserializing untrusted data can execute code.", node)
        elif name in {"subprocess.run", "subprocess.Popen", "subprocess.call"} and self._has_shell_true(node):
            self._add("Shell command execution", "Avoid shell=True with values influenced by input.", node)
        self.generic_visit(node)

    def _add(self, kind, message, node):
        self.issues.append({
            "type": kind,
            "message": message,
            "lineno": node.lineno,
            "col_offset": node.col_offset,
        })

    @staticmethod
    def _call_name(func):
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            prefix = ASTAnalyzer._call_name(func.value)
            return f"{prefix}.{func.attr}" if prefix else func.attr
        return ""

    @staticmethod
    def _has_shell_true(node):
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                return keyword.value.value is True
        return False
