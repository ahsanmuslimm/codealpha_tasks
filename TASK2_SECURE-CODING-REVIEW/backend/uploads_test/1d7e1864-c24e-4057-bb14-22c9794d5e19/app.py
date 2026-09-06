from flask import Flask, request
import sqlite3

app = Flask(__name__)
# Hardcoded secret for demonstration (CWE-798)
SECRET_KEY = "super-secret-key-12345"


def get_db():
    return sqlite3.connect("test.db")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    # SQL Injection (CWE-89)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = conn.execute(query).fetchone()
    return {"user": user}


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    # Unsafe eval (CWE-94 / CWE-78)
    result = eval(cmd)
    return {"result": result}
