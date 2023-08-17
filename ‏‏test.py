import re
import os
import sys

def run_tests(file_to_test):
    print("Running SQL injection check...")
    
    secure_patterns = [
        r'\bSELECT\b.*\bFROM\b.*\bWHERE\b.*\=\s*\?',  # Secure SELECT format
        r'\bDELETE\b.*\bFROM\b.*\bWHERE\b.*\=\s*\?',  # Secure DELETE format
        r'\bUPDATE\b.*\bSET\b.*\=\s*\?\bWHERE\b.*\=\s*\?'  # Secure UPDATE format
    ]
    not_safe = []  
    # Iterate through files in the code directory
    #for root, dirs, files in os.walk(file_to_test):
     #   for file in files:
    if file_to_test.endswith(".py"):
      #  file_path = os.path.join(root, file)
        with open(file_to_test, "r") as f:
            content_lines = f.readlines()
        is_safe = True
        line_count = 0
        for line in content_lines:
            line_count += 1
            if "query =" in line:
                if not any(re.search(pattern, line, re.IGNORECASE) for pattern in secure_patterns):
                    is_safe = False
                    print("faild")
                    return 1
        print("succes")    
        return 0
       # if not is_safe:
        #    not_safe.append((file_to_test, line_count))

   # print("SQL injection check complete.")
    #if not_safe:
     #   print("Potential SQL injection vulnerabilities found in the following files:")
      #  for file_path, line_count in not_safe:
       #     print(f"{file_path} \nLine numbers with potential vulnerabilities: {line_count}")
       # print("-" * 30)
    #else:
       # print("No SQL injection vulnerabilities found.")

def run_buffer_overflow_check(code_directory):
    print("Running buffer overflow check...")
    
    unsafe_function_patterns = unsafe_function_patterns = [
    # Existing patterns
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



    potential_vulnerabilities = {}

    for root, dirs, files in os.walk(code_directory):
        for file in files:
            if file.endswith(".c"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    c_code = f.readlines()
                vulnerabilities_in_file = []
                for line_num, line in enumerate(c_code, start=1):
                    for pattern in unsafe_function_patterns:
                        if re.search(pattern, line):
                            vulnerabilities_in_file.append(line_num)
                            break
                if vulnerabilities_in_file:
                    potential_vulnerabilities[file_path] = vulnerabilities_in_file
    
    print("Buffer Overflow check complete.")
    if potential_vulnerabilities:
        print("Potential buffer overflow vulnerabilities detected:")
        for file_path, line_numbers in potential_vulnerabilities.items():
            print(f"File: {file_path}")
            print(f"Line numbers with potential vulnerabilities: {', '.join(map(str, line_numbers))}")
        print("-" * 30)
    else:
        print("No potential vulnerabilities found.")

def run_xss_vulnerabilities_check(code_directory):
    print("Running XSS vulnerabilities check...")

    xss_patterns = [
        r'<script\b[^>]*>(.*?)<\/script>', 
        r'<[^>]+(on\w+)\s*=\s*["\'](.*?)["\']',
        r'<.*?["\'](javascript:.*?)["\'].*?>',
        r'&lt;.*?&gt;',   
    ]
    
    vulnerable_code = []

    for root, dirs, files in os.walk(code_directory):
        for file in files:
            if file.endswith((".html", ".js")):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as file:
                    code = file.readlines()
                    for line_num, line in enumerate(code, start=1):
                        for pattern in xss_patterns:
                            matches = re.findall(pattern, line)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[0]
                                if not any(keyword in match.lower() for keyword in ["javascript:", "data:"]):
                                    vulnerable_code.append((file_path, line_num, pattern))
    print("XSS vulnerabilities check complete.")
    if vulnerable_code:
        print("Potential XSS vulnerabilities found:")
        for file_path, line_num, _ in vulnerable_code:
            print(f"{file_path} \nLine numbers with potential vulnerabilities: {line_num}")
        print("-" * 30)
    else:
        print("No XSS vulnerabilities found.")


def run_xxe_vulnerabilities_check(code_directory):
    print("Running XXE vulnerabilities check...")
    
    xxe_patterns = [
        r'<!ENTITY\s+(\w+)\s+SYSTEM\s+[\'"](.*?)[\'"]>',
        r'<!DOCTYPE\s+[\w\s]*\[<!ENTITY\s+\w+\s+SYSTEM',
        r'<\?xml\s+.*?<!ENTITY\s+\w+\s+SYSTEM',
        r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]>',
        r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]\s+SYSTEM',
        r'<!ENTITY\s+\w+\s+PUBLIC\s+[\'"](.*?)[\'"]\s+[\'"](.*?)[\'"]\s*\[',
    ]
    
    xxe_vulnerabilities = []

    for root, dirs, files in os.walk(code_directory):
        for file in files:
            if file.endswith(".xml"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    content_lines = f.readlines()
                for line_num, line in enumerate(content_lines, start=1):
                    for pattern in xxe_patterns:
                        if re.search(pattern, line):
                            xxe_vulnerabilities.append((file_path, line_num))
                            break
    print("XXE vulnerabilities check complete.")                       
    if xxe_vulnerabilities:
        print("XXE vulnerabilities found:")
        for file_path, line_num in xxe_vulnerabilities:
                print(f"{file_path} \nLine numbers with potential vulnerabilities: {line_num}")
        print("-" * 30)
    else:
        print("No XXE vulnerabilities found.")



def run_sensitive_data_check(code_directory):
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

    for root, dirs, files in os.walk(code_directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    content_lines = f.readlines()
                for line_num, line in enumerate(content_lines, start=1):
                    for pattern in sensitive_data_patterns:
                        if re.search(pattern, line):
                            sensitive_data.append((file_path, line_num))
                            break
    print("Sensitive data check complete.")                       
    if sensitive_data:
        print("Sensitive data exposure found:")
        for file_path, line_num in sensitive_data:
            print(f"{file_path} \nLine numbers with potential vulnerabilities: {line_num}")
        print("-" * 30)
    else:
        print("No sensitive data exposure found.")



#code_directory_path = r'C:\Users\לירן\Desktop\Liran_Chaimjan_Shani_kaminitz\file_to_check'
#run_sql_injection_check(code_directory_path)
#run_buffer_overflow_check(code_directory_path)
#run_xss_vulnerabilities_check(code_directory_path)
#run_sensitive_data_check(code_directory_path)
#run_xxe_vulnerabilities_check(code_directory_path)
file_to_test = sys.argv[1]
run_tests(file_to_test)