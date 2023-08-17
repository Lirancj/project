import subprocess
import os
from pathlib import Path

example_files = os.listdir('tests/examples')
for i in range(len(example_files)):
    file = example_files[i]
    print(f"Running tests for {file}")
    process = subprocess.run(["python", "vulnerabilities_scanner.py", f'tests/examples/{file}'])
    exit_code = process.returncode
    print(f"Exit code for {file}: {exit_code}")

    if exit_code != 1:
        print(f"Vulnerability was not detected in {file}")
        exit(1)
