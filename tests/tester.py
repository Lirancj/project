import subprocess
import os
from pathlib import Path

examples_path = Path(os.getcwd()) / 'examples'

example_files = os.listdir(examples_path)

for file in example_files:
    print(f"Running tests for {file}")
    process = subprocess.run(["python", "/vulnerabilities_scanner.py", file])
    exit_code = process.returncode
    print(f"Exit code for {file}: {exit_code}")

    if exit_code != 1:
        print(f"Vulnerability was not detected in {file}")
        exit(1)
