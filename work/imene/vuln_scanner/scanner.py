import os
import re
import sys
RULES = [
    ("R1", re.compile(r"\beval\s*\("), "eval() detected – dynamic execution"),
    ("R2", re.compile(r"\bos\.system\s*\("), "os.system() detected – shell command"),
    ("R2", re.compile(r"subprocess\.run\s*\(\s*[\"']"),
     "subprocess.run() called with a string command – dangerous"),
    ("R2", re.compile(r"subprocess\.run\s*\(.*\+.*\)"),
     "subprocess.run() command built by concatenation – dangerous"),
    ("R2", re.compile(r"shell\s*=\s*True"),
     "subprocess.run() with shell=True – dangerous"),

    ("R3", re.compile(r"SELECT.+\+"), "SQL built using string concatenation – possible SQL injection"),
    ("R3", re.compile(r"f[\"'].*SELECT.*\{.*\}"), "SQL built using f-string – possible SQL injection"),
]

EXCLUDED_DIRS = {"__pycache__", ".venv", "env", "venv", "node_modules"}

def scan_file(path: str):
    findings = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        # If we can't read the file, skip it
        return findings

    for lineno, line in enumerate(lines, start=1):
        # Remove anything after '#' (inline or full-line comment)
        code_only = line.split("#")[0]

        # Skip empty lines after removing comments
        if code_only.strip() == "":
            continue

        for rule_id, pattern, message in RULES:
            if pattern.search(code_only):
                findings.append((path, lineno, rule_id, message))

    return findings


def walk_and_scan(target_path: str):
    results = []

    # If the target is a single file
    if os.path.isfile(target_path):
        return scan_file(target_path)

    # Otherwise, walk through directories
    for root, dirs, files in os.walk(target_path):
        # Remove excluded directories from the search
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for filename in files:
            if filename.endswith(".py"):
                full_path = os.path.join(root, filename)
                results.extend(scan_file(full_path))

    return results

def main():
    # default scan path = project root
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    print("Security scan started")
    print(f"Scanning: {target}")
    print("Rules: R1(eval), R2(shell exec), R3(SQL concat/f-string)")

    findings = walk_and_scan(target)

    if not findings:
        print("No vulnerabilities found.")
        print("Summary: 0 findings")
        sys.exit(0)

    for file_path, lineno, rule_id, message in findings:
        print(f"{file_path}:{lineno}:{rule_id}: {message} | severity:high")

    print(f"Summary: {len(findings)} findings (high)")
    sys.exit(2)


if __name__ == "__main__":
    main()

