import subprocess
import os

example_files = os.listdir('tests/examples')


for file in example_files:
    print(f"Running tests for {file}")
    process = subprocess.run(
        ["python", "vulnerabilities_scanner.py", f'tests/examples/{file}'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    exit_code = process.returncode
    print(f"Exit code for {file}: {exit_code}")

    if exit_code != 1:
        print(f"Vulnerability was not detected in {file}")
        exit(1)
