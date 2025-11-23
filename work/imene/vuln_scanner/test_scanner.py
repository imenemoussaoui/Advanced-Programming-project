import os
import unittest
import sys
import subprocess

def run_scanner(path):
    # Absolute path to this test file
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Absolute path to scanner.py
    scanner_path = os.path.join(base_dir, "scanner.py")

    print("DEBUG SCANNER PATH:", scanner_path)  # Optional debug

    # FINAL: run scanner.py directly with Python
    result = subprocess.run(
        [sys.executable, scanner_path, path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return result.stdout, result.returncode

class ScannerTests(unittest.TestCase):
    def test_eval_detection(self):
        out, code = run_scanner("scanner-fixtures/T1_eval.py")
        self.assertIn("R1", out)
        self.assertEqual(code, 2)

    def test_shell_detection(self):
        out, code = run_scanner("scanner-fixtures/T2_shell_concat.py")
        self.assertIn("R2", out)
        self.assertEqual(code, 2)

    def test_sql_detection(self):
        out, code = run_scanner("scanner-fixtures/T3_sql_concat.py")
        self.assertIn("R3", out)
        self.assertEqual(code, 2)

    def test_safe_file(self):
        out, code = run_scanner("scanner-fixtures/T4_safe.py")
        self.assertNotIn("severity:high", out)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()