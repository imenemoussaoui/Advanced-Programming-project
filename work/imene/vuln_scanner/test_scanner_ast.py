import unittest
import subprocess
import sys
import os

def run_ast_scanner(path):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scanner_path = os.path.join(base_dir, "scanner_ast.py")
    full_path = os.path.join(base_dir, "scanner-fixtures", path)

    result = subprocess.run(
        [sys.executable, scanner_path, full_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout, result.returncode


class TestASTScanner(unittest.TestCase):

    # ---- R1 : eval ----
    def test_eval(self):
        out, code = run_ast_scanner("T1_eval.py")
        self.assertIn("R1", out)
        self.assertEqual(code, 2)

    # ---- R1 : exec ----
    def test_exec(self):
        out, code = run_ast_scanner("T1b_exec.py")
        self.assertIn("R1", out)
        self.assertEqual(code, 2)

    # ---- R2 : os.system ----
    def test_os_system(self):
        out, code = run_ast_scanner("T2_shell.py")
        self.assertIn("R2", out)
        self.assertEqual(code, 2)

    # ---- R2 : subprocess.run(shell=True) ----
    def test_subprocess_shell(self):
        out, code = run_ast_scanner("T2b_subprocess.py")
        self.assertIn("R2", out)
        self.assertEqual(code, 2)

    # ---- R3 : SQL concat ----
    def test_sql_concat(self):
        out, code = run_ast_scanner("T3_sql_concat.py")
        self.assertIn("R3", out)
        self.assertEqual(code, 2)

    # ---- R3 : SQL % ----
    def test_sql_percent(self):
        out, code = run_ast_scanner("T3b_sql_percent.py")
        self.assertIn("R3", out)
        self.assertEqual(code, 2)

    # ---- R3 : SQL .format ----
    def test_sql_format(self):
        out, code = run_ast_scanner("T3c_sql_format.py")
        self.assertIn("R3", out)
        self.assertEqual(code, 2)

    # ---- R3 : SQL f-string ----
    def test_sql_fstring(self):
        out, code = run_ast_scanner("T3d_sql_fstring.py")
        self.assertIn("R3", out)
        self.assertEqual(code, 2)

    # ---- R4 : dangerous imports ----
    def test_import_pickle(self):
        out, code = run_ast_scanner("T4_import_pickle.py")
        self.assertIn("R4", out)
        self.assertEqual(code, 2)

    # ---- R6 : weak crypto ----
    def test_weak_crypto(self):
        out, code = run_ast_scanner("T4_import_hashlib.py")
        self.assertIn("R6", out)
        self.assertEqual(code, 2)

    # ---- R5 : hardcoded secrets ----
    def test_hardcoded_secrets(self):
        out, code = run_ast_scanner("T5_secrets.py")
        self.assertIn("R5", out)
        self.assertEqual(code, 2)

    # ---- R7 : input ----
    def test_input(self):
        out, code = run_ast_scanner("T6_input.py")
        self.assertIn("R7", out)
        self.assertEqual(code, 2)

    # ---- SAFE FILE ----
    def test_safe(self):
        out, code = run_ast_scanner("T7_safe.py")
        # must NOT contain any rule id
        self.assertNotIn("R1", out)
        self.assertNotIn("R2", out)
        self.assertNotIn("R3", out)
        self.assertNotIn("R4", out)
        self.assertNotIn("R5", out)
        self.assertNotIn("R6", out)
        self.assertNotIn("R7", out)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
