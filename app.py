
import os
import math
import logging
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Optional: load .env (local defaults still work if .env is absent) ---
try:
    from dotenv import load_dotenv
    from pathlib import Path
    env_path = Path(__file__).with_name(".env")
    load_dotenv(dotenv_path=env_path, override=True)
except Exception:
    pass

# Basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "replace-with-a-secret-key-123")  # change in prod

def get_conn():
    """Return a new MySQL connection (local defaults work without .env)."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "host.docker.internal"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME", "todo_db"),
    )

# --- Auth helpers ---
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper

def get_user_by_username(username):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        return user
    finally:
        cur.close()
        conn.close()

def create_user(username, password):
    """Create a new user (hashed password). Returns (ok, error_msg)."""
    username = (username or "").strip()
    password = (password or "")

    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"

    # Check duplicate
    if get_user_by_username(username):
        return False, "Username already exists"

    pwd_hash = generate_password_hash(password)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, pwd_hash))
        conn.commit()
        return True, None
    finally:
        cur.close()
        conn.close()

def seed_user():
    """Seed a default user once (non-fatal if DB is down)."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE username = %s", ("manojit",))
        exists = cur.fetchone()[0]
        if exists == 0:
            pwd_hash = generate_password_hash("test123")
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", ("manojit", pwd_hash))
            conn.commit()
            logging.info("[seed_user] created user 'manojit'")
    finally:
        cur.close()
        conn.close()
def safe_seed_user():
    try:
        seed_user()
    except Exception as e:
        logging.warning(f"[WARN] seed_user failed: {e}")

safe_seed_user()

# --- Health route to verify DB connectivity quickly ---
@app.get("/db-health")
def db_health():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({"db": "ok"}), 200
    except Exception as e:
        logging.exception("DB health check failed")
        return jsonify({"db": "error", "detail": str(e)}), 500

# --- Login / Logout / Signup ---
@app.get("/login")
def login():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("login.html")

@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    try:
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password")
    except Exception:
        logging.exception("Error in /login")
        return render_template("login.html", error="Internal error"), 500

@app.get("/logout")
def logout():
    session.clear()  # does NOT delete tasks/data
    return redirect(url_for("login"))

@app.get("/signup")
def signup():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("signup.html")

@app.post("/signup")
def signup_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm", "")

    if password != confirm:
        return render_template("signup.html", error="Passwords do not match", username=username)

    ok, err = create_user(username, password)
    if not ok:
        return render_template("signup.html", error=err, username=username)

    # Auto-login after signup
    user = get_user_by_username(username)
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("index"))

# --- Todo routes (protected) ---
@app.get("/")
@login_required
def index():
    page_size = 10
    page = request.args.get("page", 1, type=int)
    page = max(1, page)
    user_id = session["user_id"]

    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        # Count only this user's tasks
        cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE user_id = %s", (user_id,))
        total_tasks = cur.fetchone()["c"]
        total_pages = max(1, math.ceil(total_tasks / page_size))

        # Fetch only this user's tasks
        cur.execute("""
            SELECT id, title, completed
            FROM tasks
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """, (user_id, page_size, (page - 1) * page_size))
        tasks = cur.fetchall()
        return render_template("index.html", tasks=tasks, page=page, total_pages=total_pages)
    finally:
        cur.close()
        conn.close()

@app.post("/tasks")
@login_required
def create_task():
    title = request.form.get("title", "").strip()
    page = request.args.get("page", 1, type=int)
    user_id = session["user_id"]

    if title:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO tasks (title, completed, user_id) VALUES (%s, %s, %s)",
                (title, False, user_id)
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()
    return redirect(url_for("index", page=page))

@app.post("/tasks/<int:task_id>/toggle")
@login_required
def toggle_task(task_id):
    user_id = session["user_id"]
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        # Ensure task belongs to the current user
        cur.execute("SELECT id, completed FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
        task = cur.fetchone()
        if not task:
            return jsonify({"error": "Task not found"}), 404

        # Toggle completion
        cur.execute("UPDATE tasks SET completed = NOT completed WHERE id = %s AND user_id = %s", (task_id, user_id))
        conn.commit()

        # Get updated value
        cur.execute("SELECT completed FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
        completed = cur.fetchone()["completed"]
        return jsonify({"id": task_id, "completed": bool(completed)})
    finally:
        cur.close()
        conn.close()

@app.post("/tasks/<int:task_id>/delete")
@login_required
def delete_task(task_id):
    page = request.args.get("page", 1, type=int)
    user_id = session["user_id"]

    conn = get_conn()
    try:
        cur = conn.cursor()
        # Delete only if owned by current user
        cur.execute("DELETE FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    return redirect(url_for("index", page=page))

if __name__ == "__main__":
    # Run locally on port 8000
    app.run(host="0.0.0.0", port=8000, debug=True)
