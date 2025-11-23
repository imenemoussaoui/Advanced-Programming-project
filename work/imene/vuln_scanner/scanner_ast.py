import ast
import sys
import os

DANGEROUS_IMPORTS = {
    "pickle",
    "subprocess",
    "tempfile",
}

WEAK_CRYPTO_FUNCS = {"md5", "sha1"}

SECRET_KEYWORDS = {
    "password", "pwd", "passwd", "secret", "token",
    "api_key", "apikey", "key"
}


class ASTScanner(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []

    def report(self, node, rule_id, message):
        lineno = getattr(node, 'lineno', '?')
        self.findings.append((self.filename, lineno, rule_id, message))

    # ============================================================
    # MAIN visit_Call (first entry point for any function call)
    # ============================================================
    def visit_Call(self, node):
        # R7: input()
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            self.report(node, "R7", "input() used – untrusted input source")

        # Use helper for all core rules
        self.handle_call_rules(node)

        self.generic_visit(node)

    # ============================================================
    # All call-based rules here
    # ============================================================
    def handle_call_rules(self, node):

        # -------- R1: eval() --------
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.report(node, "R1", "eval() detected – dynamic execution")

        # -------- R1: exec() --------
        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            self.report(node, "R1", "exec() detected – dynamic execution")

        # -------- R2: os.system() --------
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "system"
            ):
                self.report(node, "R2", "os.system() detected – shell command")

        # -------- R2: subprocess.run(shell=True) --------
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr == "run"
            ):
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        self.report(node, "R2", "subprocess.run(shell=True) detected")

        # -------- R3: SQL .format() --------
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
                and "SELECT" in node.func.value.value.upper()
                and node.func.attr == "format"
            ):
                self.report(node, "R3", "SQL built using .format() (dangerous)")

        # -------- R6: weak crypto (md5, sha1) --------
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr in WEAK_CRYPTO_FUNCS
            ):
                self.report(node, "R6", f"Weak crypto detected: hashlib.{node.func.attr}()")

    # ============================================================
    # R3: SQL CONCAT & SQL % formatting
    # ============================================================
    def visit_BinOp(self, node):
        # SQL concatenation: "SELECT ..." + something
        if isinstance(node.op, ast.Add):
            left = node.left
            right = node.right
            if (
                isinstance(left, ast.Constant)
                and isinstance(left.value, str)
                and "SELECT" in left.value.upper()
            ) or (
                isinstance(right, ast.Constant)
                and isinstance(right.value, str)
                and "SELECT" in right.value.upper()
            ):
                self.report(node, "R3", "SQL built using + concatenation (dangerous)")

        # SQL % formatting: "SELECT ..." % var
        if isinstance(node.op, ast.Mod):
            left = node.left
            if (
                isinstance(left, ast.Constant)
                and isinstance(left.value, str)
                and "SELECT" in left.value.upper()
            ):
                self.report(node, "R3", "SQL built using % formatting (dangerous)")

        self.generic_visit(node)

    # ============================================================
    # R3: SQL f-strings
    # ============================================================
    def visit_JoinedStr(self, node):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if "SELECT" in value.value.upper():
                    self.report(node, "R3", "SQL built using f-string (dangerous)")
        self.generic_visit(node)

    # ============================================================
    # R4: dangerous imports + weak crypto imports
    # ============================================================
    def visit_Import(self, node):
        for alias in node.names:
            # dangerous imports
            if alias.name in DANGEROUS_IMPORTS:
                self.report(node, "R4", f"Dangerous import detected: {alias.name}")

            # weak crypto potential
            if alias.name == "hashlib":
                self.report(node, "R4", "hashlib imported (check for weak hashes)")

        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in DANGEROUS_IMPORTS:
            self.report(node, "R4", f"Dangerous import detected: from {node.module}")

        if node.module == "hashlib":
            for alias in node.names:
                if alias.name in WEAK_CRYPTO_FUNCS:
                    self.report(node, "R6", f"Weak crypto imported: hashlib.{alias.name}")

        self.generic_visit(node)

    # ============================================================
    # R5: hardcoded secrets
    # ============================================================
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var = target.id.lower()
                if any(key in var for key in SECRET_KEYWORDS):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) >= 6:
                            self.report(
                                node,
                                "R5",
                                f"Hardcoded secret detected in '{target.id}'"
                            )

        self.generic_visit(node)


# ============================================================
# SCAN ENGINE
# ============================================================
def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        tree = ast.parse(src)
    except Exception:
        return []

    scanner = ASTScanner(path)
    scanner.visit(tree)
    return scanner.findings


def walk_and_scan(target_path):
    results = []
    if os.path.isfile(target_path):
        return scan_file(target_path)

    for root, dirs, files in os.walk(target_path):
        for f in files:
            if f.endswith(".py"):
                full = os.path.join(root, f)
                results.extend(scan_file(full))
    return results


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print("AST Security scan started")
    print(f"Scanning: {target}")
    findings = walk_and_scan(target)

    if not findings:
        print("No vulnerabilities found.")
        print("Summary: 0 findings")
        sys.exit(0)

    for f, line, rule, msg in findings:
        print(f"{f}:{line}:{rule}: {msg}")

    print(f"Summary: {len(findings)} findings")
    sys.exit(2)


if __name__ == "__main__":
    main()
