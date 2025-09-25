
import sqlite3
from flask import request

def secure_sql_query(user_id):
    """Secure SQL Query Execution"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Secure: Using parameterized queries
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # Secure: Using parameterized queries
    query2 = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query2, (user_id,))

    # Secure: Using parameterized queries
    username = request.args.get('username')
    query3 = "SELECT * FROM accounts WHERE username = ?"
    cursor.execute(query3, (username,))

    return cursor.fetchall()

def vulnerable_sql_injection_order_by(sort_column):
    """CWE-89: SQL Injection in ORDER BY"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Unvalidated column name in ORDER BY
    query = f"SELECT * FROM products ORDER BY {sort_column}"
    cursor.execute(query)
    
    return cursor.fetchall()

# ============================================================================
# 2. COMMAND INJECTION VULNERABILITIES
# ============================================================================

def vulnerable_command_injection(filename):
    """CWE-78: OS Command Injection"""
    # VULNERABLE: Direct command execution
    os.system(f"cat {filename}")
    
    # VULNERABLE: Shell=True with user input
    subprocess.call(f"echo {filename}", shell=True)
    
    # VULNERABLE: Using os.popen
    result = os.popen(f"ls -la {filename}").read()
    
    # VULNERABLE: subprocess.run with shell=True
    subprocess.run(["sh", "-c", f"grep pattern {filename}"])
    
    return result

def vulnerable_eval_injection(user_input):
    """CWE-95: Eval Injection"""
    # VULNERABLE: Direct eval of user input
    result = eval(user_input)
    
    # VULNERABLE: exec with user input
    exec(f"value = {user_input}")
    
    return result