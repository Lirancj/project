import subprocess
import os
from pathlib import Path

example_files = map(lambda path: Path(path), os.listdir('tests/examples'))


for file in example_files:
    absolute_file = file.resolve()
    print(f"Running tests for {file}")
    process = subprocess.run(["python", "vulnerabilities_scanner.py", absolute_file])
    exit_code = process.returncode
    print(f"Exit code for {file}: {exit_code}")

    if exit_code != 1:
        print(f"Vulnerability was not detected in {file}")
        exit(1)
