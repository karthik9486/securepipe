# Demo-only file with intentionally planted issues, used to show
# SecurePipe catching problems before faculty review.
# DO NOT use these patterns in real student submissions.

import sqlite3

# --- Planted issue 1: hardcoded credential (Gitleaks should flag this) ---
AWS_ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP"
DB_PASSWORD = "SuperSecret123!"


def get_student_record(student_id):
    # --- Planted issue 2: SQL injection via string concatenation
    # (Semgrep should flag this) ---
    conn = sqlite3.connect("students.db")
    query = "SELECT * FROM students WHERE id = '" + student_id + "'"
    return conn.execute(query).fetchall()


def run_user_expression(expr):
    # --- Planted issue 3: use of eval() on untrusted input
    # (Semgrep should flag this) ---
    return eval(expr)


if __name__ == "__main__":
    print(get_student_record("1"))
