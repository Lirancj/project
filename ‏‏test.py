import re
import os
import sys

import os
import re

def run_tests(file_to_test):
    print("Running SQL injection check...")
    
    secure_patterns = [
        r'\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\=\s*\?',  # Secure SELECT format
        r'\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\=\s*\?',  # Secure DELETE format
        r'\bUPDATE\b.*\bSET\b.*\=\s*\?\bWHERE\b.*\=\s*\?'  # Secure UPDATE format
    ]
    
    
    # Iterate through files in the code directory
    # for root, dirs, files in os.walk(file_to_test):
    #     for file in files:
    if file_to_test.endswith(".py") or file_to_test.endswith(".c") or file_to_test.endswith(".xml")or file_to_test.endswith(".js"):
        with open(file_to_test, "r") as f:
            content_lines = f.readlines()
        is_safe = True
        line_count = 0
        for line in content_lines:
            line_count += 1
            if "query =" in line:
                if not any(re.search(pattern, line, re.IGNORECASE) for pattern in secure_patterns):
                    is_safe = False
                    break
                      # Exit the loop on the first vulnerability
        if is_safe:
            print("succes")
        else:
            print("fail.")
            return 1
    
    
    print("Running sensitive data check...")
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
    sensitive_data = []

    if file_to_test.endswith(".py") or file_to_test.endswith(".c") or file_to_test.endswith(".xml")or file_to_test.endswith(".js"):
        with open(file_to_test, "r") as f:
            content_lines = f.readlines()
        for line_num, line in enumerate(content_lines, start=1):
            for pattern in sensitive_data_patterns:
                if re.search(pattern, line):
                    sensitive_data.append((file_to_test, line_num))
                    is_safe = False
                    break
                   
                    
    if sensitive_data:
        print("failed")
        return 1
    else:
        print("success")
        
        
    unsafe_function_patterns = [
    r'\[\s*([a-zA-Z_]\w*)\s*\]\s*=\s*\w+\s*;',
    r'strcpy\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*\)',
    r'strcat\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*\)',
    r'sprintf\s*\(\s*([a-zA-Z_]\w*)\s*,\s*[^"]*"\s*,\s*([a-zA-Z_]\w*)\s*\)',
    r'gets\s*\(\s*([a-zA-Z_]\w*)\s*\)',
    r'memcpy\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*,\s*sizeof\s*\(\s*([a-zA-Z_]\w*)\s*\)\s*\)\s*;',
    r'memcpy\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*,\s*\w+\s*\)',
    r'memmove\s*\(\s*([a-zA-Z_]\w*)\s*,\s*([a-zA-Z_]\w*)\s*,\s*\w+\s*\)',
    r'gets_s\s*\(\s*([a-zA-Z_]\w*)\s*,\s*\w+\s*\)',
    r'scanf\s*\(\s*[^"]*"\s*,\s*([a-zA-Z_]\w*)\s*\)',
    r'sscanf\s*\(\s*[^"]*"\s*,\s*([a-zA-Z_]\w*)\s*,\s*&[a-zA-Z_]\w*\s*\)',
    r'malloc\s*\(\s*\w+\s*\)',
    r'calloc\s*\(\s*\w+\s*,\s*\w+\s*\)',
    r'realloc\s*\(\s*[^"]*"\s*,\s*\w+\s*\)',
    r'alloca\s*\(\s*\w+\s*\)',
    r'(\w+)\s*=\s*\(\w+\*\)\s*calloc\s*\(\s*(\w+)\s*,\s*sizeof\s*\(\s*(\w+)\s*\)\s*\);',
]
    print("Running buffer overflow check...")    
    potential_vulnerabilities = {}
    if file_to_test.endswith(".py") or file_to_test.endswith(".c") or file_to_test.endswith(".xml")or file_to_test.endswith(".js"):
        with open(file_to_test, "r") as f:
            c_code = f.readlines()
        vulnerabilities_in_file = []
        for line_num, line in enumerate(c_code, start=1):
            for pattern in unsafe_function_patterns:
                if re.search(pattern, line):
                    vulnerabilities_in_file.append(line_num)
                   
                    break
        if vulnerabilities_in_file:
            potential_vulnerabilities[file_to_test] = vulnerabilities_in_file

    if potential_vulnerabilities:
        print("fail")
        return 1
    else:
        print("success")

    print("Running XSS vulnerabilities check...")

    xss_patterns = [
        r'<script\b[^>]*>(.*?)<\/script>', 
        r'<[^>]+(on\w+)\s*=\s*["\'](.*?)["\']',
        r'<.*?["\'](javascript:.*?)["\'].*?>',
        r'&lt;.*?&gt;',   
    ]
 
    vulnerable_code = []
    if file_to_test.endswith((".html", ".js")):
        with open(file_to_test, 'r') as file_to_test:
            code = file_to_test.readlines()
            for line_num, line in enumerate(code, start=1):
                for pattern in xss_patterns:
                    matches = re.findall(pattern, line)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if not any(keyword in match.lower() for keyword in ["javascript:", "data:"]):
                            vulnerable_code.append((file_to_test, line_num, pattern))
                            break
    if vulnerable_code:
        print("fail")
        return 1
    else:
        print("success")

    xxe_patterns = [
    r'<!ENTITY\s+(\w+)\s+SYSTEM\s+[\'"](.*?)[\'"]>',
    r'<!DOCTYPE\s+[\w\s]*\[<!ENTITY\s+\w+\s+SYSTEM',
    r'<\?xml\s+.*?<!ENTITY\s+\w+\s+SYSTEM',
    r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]>',
    r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]\s+SYSTEM',
    r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]\s*\[',
    ]
    print("Running XXE vulnerabilities check...")

    xxe_vulnerabilities = []
    if file_to_test.endswith(".xml"):
        with open(file_to_test, "r") as f:
            content_lines = f.readlines()
        for line_num, line in enumerate(content_lines, start=1):
            for pattern in xxe_patterns:
                if re.search(pattern, line):
                    xxe_vulnerabilities.append((file_to_test, line_num))
                    return 1
                    break                
    if xxe_vulnerabilities:
        print("fail")
        return 1
    else:
        print("success")
    return 0


#code_directory_path = r'C:\Users\לירן\Desktop\Liran_Chaimjan_Shani_kaminitz\file_to_check'
#run_sql_injection_check(code_directory_path)
#run_buffer_overflow_check(code_directory_path)
#run_xss_vulnerabilities_check(code_directory_path)
#run_sensitive_data_check(code_directory_path)
#run_xxe_vulnerabilities_check(code_directory_path)
file_to_test = sys.argv[1]
run_tests(file_to_test)