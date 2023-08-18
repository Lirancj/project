import re
import sys
from pathlib import Path


class VulnerableCodeException(Exception):
    pass


def run_all_tests(file_path: Path) -> None:
    run_sql_injection_check(file_path)
    run_xss_vulnerabilities_check(file_path)
    run_buffer_overflow_check(file_path)
    run_sensitive_data_check(file_path)
    run_xxe_vulnerabilities_check(file_path)


def run_sql_injection_check(file_path: Path) -> None:
    print(f"Running SQL injection check for {file_path}...")

    secure_patterns = [
        r"\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\=\s*\?",  # Secure SELECT format
        r"\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\=\s*\?",  # Secure DELETE format
        r"\bUPDATE\b.*\bSET\b.*\=\s*\?\bWHERE\b.*\=\s*\?",  # Secure UPDATE format
        r"\bINSERT\b.*\bINTO\b.*\bVALUES\b\s*\(\s*\?\s*\)",  # Secure INSERT format
    ]

    # Iterate through files in the code directory
    # for root, dirs, files in os.walk(file_path):
    #     for file in files:
    with open(file_path, mode="r") as file:
        content_lines = file.readlines()

    for line in content_lines:
        if "query =" in line:
            if not any(re.search(pattern, line, re.IGNORECASE) for pattern in secure_patterns):
                raise VulnerableCodeException(f"Vulnerable SQL query found in {file_path}!, line: " + line)
                # Exit the loop on the first vulnerability

    print(f"Sql injection check for {file_path} passed successfully")


def run_buffer_overflow_check(file_path: Path):
    print(f"Running buffer overflow check for {file_path}...")

    unsafe_function_patterns = [
        r"\[\s*([a-zA-Z_]\w*)\s*\]\s*=\s*\w+\s*;",
        r"strcpy\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*\)",
        r"strcat\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*\)",
        r'sprintf\s*\(\s*([a-zA-Z_]\w*)\s*,\s*[^"]*"\s*,\s*([a-zA-Z_]\w*)\s*\)',
        r"gets\s*\(\s*([a-zA-Z_]\w*)\s*\)",
        r"memcpy\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*,\s*sizeof\s*\(\s*([a-zA-Z_]\w*)\s*\)\s*\)\s*;",
        r"memcpy\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*,\s*\w+\s*\)",
        r"memmove\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*,\s*\w+\s*\)",
        r"gets_s\s*\(\s*([a-zA-Z_]\w*)\s*,\s*\w+\s*\)",
        r'scanf\s*\(\s*[^"]*"\s*,\s*([a-zA-Z_]\w*)\s*\)',
        r'sscanf\s*\(\s*[^"]*"\s*,\s*([a-zA-Z_]\w*)\s*,\s*&[a-zA-Z_]\w*\s*\)',
        r"malloc\s*\(\s*\w+\s*\)",
        r"calloc\s*\(\s*\w+\s*,\s*\w+\s*\)",
        r'realloc\s*\(\s*[^"]*"\s*,\s*\w+\s*\)',
        r"alloca\s*\(\s*\w+\s*\)",
        r"(\w+)\s*=\s*\(\w+\*\)\s*calloc\s*\(\s*(\w+)\s*,\s*sizeof\s*\(\s*(\w+)\s*\)\s*\);",
    ]

    potential_vulnerabilities = {}
    with open(file_path, mode="r") as file:
        c_code = file.readlines()

    for line_num, line in enumerate(c_code, start=1):
        for pattern in unsafe_function_patterns:
            if re.search(pattern, line):
                raise VulnerableCodeException(f"Vulnerable function found in {file_path}!, line: " + line)

    print(f"Buffer overflow check for {file_path} passed successfully")


def run_xss_vulnerabilities_check(file_path: Path):
    print(f"Running XSS vulnerabilities check for {file_path}...")

    xss_patterns = [
        r"<script\b[^>]*>(.*?)<\/script>",
        r'<[^>]+(on\w+)\s*=\s*["\'](.*?)["\']',
        r'<.*?["\'](javascript:.*?)["\'].*?>',
        r"&lt;.*?&gt;",
    ]

    with open(file_path, mode="r") as file_path:
        code = file_path.readlines()
        for line_num, line in enumerate(code, start=1):
            for pattern in xss_patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if not any(keyword in match.lower() for keyword in ["javascript:", "data:"]):
                        raise VulnerableCodeException(f"Vulnerable code found in {file_path}!, line: " + line)

    print(f"XSS vulnerabilities check for {file_path} passed successfully")


def run_sensitive_data_check(file_path: Path):
    print(f"Running sensitive data check for {file_path}...")
    sensitive_data_patterns = [
        r'(\b(?:password|api_key|secret)\b)\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'AWS_ACCESS_KEY\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'AWS_SECRET_KEY\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'Authorization\s*:\s*[\'"]Bearer\s+([^\'"]+)[\'"]',
        r'apikey\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'session_id\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'client_secret\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'token\s*=\s*[\'"]([^\'"]+)[\'"]',
    ]

    with open(file_path, "r") as f:
        content_lines = f.readlines()
    for line_num, line in enumerate(content_lines, start=1):
        for pattern in sensitive_data_patterns:
            if re.search(pattern, line):
                raise VulnerableCodeException(f"Sensitive data found in {file_path}!, line: " + line)

    print(f"Sensitive data check for {file_path} passed successfully")


def run_xxe_vulnerabilities_check(file_path: Path):
    print(f"Running XXE vulnerabilities check for {file_path}...")

    xxe_patterns = [
        r'<!ENTITY\s+(\w+)\s+SYSTEM\s+[\'"](.*?)[\'"]>',
        r"<!DOCTYPE\s+[\w\s]*\[<!ENTITY\s+\w+\s+SYSTEM",
        r"<\?xml\s+.*?<!ENTITY\s+\w+\s+SYSTEM",
        r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]>',
        r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]\s+SYSTEM',
        r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]\s*\[',
    ]

    with open(file_path, "r") as f:
        content_lines = f.readlines()
    for line_num, line in enumerate(content_lines, start=1):
        for pattern in xxe_patterns:
            if re.search(pattern, line):
                raise VulnerableCodeException(f"XXE vulnerability found in {file_path}!, line: " + line)

    print(f"XXE vulnerabilities check for {file_path} passed successfully")


def main():
    files_to_scan = sys.argv[1:]
    for file in files_to_scan:
        file_path = Path(file)
        if not file_path.is_file():
            raise FileNotFoundError(f"File {file} does not exist.")
        run_all_tests(file_path)


if __name__ == "__main__":
    main()
