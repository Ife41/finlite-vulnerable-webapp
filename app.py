"""
FinLite: A demo fintech-style organization web app used to practice and
demonstrate multiple vulnerability classes. Each intentional vulnerability
is clearly commented with a VULN tag.

INTENTIONALLY VULNERABLE. For isolated lab use only, never expose this
to an untrusted network or the public internet.
"""

from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from functools import wraps
import sqlite3
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB_PATH = os.path.join(os.path.dirname(__file__), "finlite.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def find_user_by_username(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def create_starter_invoices(user_id, username):
    conn = get_db()
    conn.execute(
        "INSERT INTO invoices (owner_id, amount, description) VALUES (?, ?, ?)",
        (user_id, 49.99, f"Welcome package - {username}")
    )
    conn.execute(
        "INSERT INTO invoices (owner_id, amount, description) VALUES (?, ?, ?)",
        (user_id, 15.00, "Account setup fee")
    )
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper


def login_required_ui(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_session_username():
    return {"session_username": session.get("username")}


@app.route("/")
def index():
    return jsonify({
        "app": "FinLite Demo API (intentionally vulnerable)",
        "status": "running",
        "web_ui": "/ui/login",
        "endpoints": [
            "/login", "/logout", "/me",
            "/api/register",
            "/invoices/<id>",
            "/invoices/all",
            "/invoices/search?q=",
        ]
    })


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = find_user_by_username(username)

    # VULN A: Broken Authentication, different error messages leak
    # whether a username exists, before password verification happens.
    if not user:
        return jsonify({"error": "User does not exist"}), 401

    if user["password"] != password:
        return jsonify({"error": "Incorrect password"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    return jsonify({"message": f"Logged in as {user['username']}", "user_id": user["id"]})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/me")
@login_required
def me():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"]})


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}

    if not data.get("username") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "username, email, and password are required"}), 400

    if find_user_by_username(data["username"]):
        return jsonify({"error": "Username already taken"}), 409

    conn = get_db()
    try:
        # VULN E: Mass Assignment, every client-supplied field is
        # inserted directly, including "role" if present. No whitelist
        # restricts which fields the client may set.
        cursor = conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (
                data["username"],
                data["email"],
                data["password"],
                data.get("role", "customer"),
            ),
        )
        conn.commit()
        new_user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username or email already exists"}), 409
    conn.close()

    create_starter_invoices(new_user_id, data["username"])

    return jsonify({"message": "Account created", "username": data["username"]}), 201


@app.route("/ui/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html", error=None)

    username = request.form.get("username", "")
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    if not username or not email or not password:
        return render_template("register.html", error="All fields are required")

    if find_user_by_username(username):
        return render_template("register.html", error="Username already taken")

    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'customer')",
            (username, email, password),
        )
        conn.commit()
        new_user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return render_template("register.html", error="Username or email already exists")
    conn.close()

    create_starter_invoices(new_user_id, username)

    flash("Account created - please sign in")
    return redirect(url_for("login_page"))


@app.route("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    conn = get_db()
    invoice = conn.execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    conn.close()

    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404

    # VULN B: IDOR  no check that invoice["owner_id"] == session["user_id"]
    return jsonify(dict(invoice))


@app.route("/invoices/all")
@login_required
def get_all_invoices():
    # VULN C: IDOR via trusted client header, a client-supplied header
    # decides admin access instead of checking the real role in the DB.
    is_admin_header = request.headers.get("X-Admin", "false").lower() == "true"

    conn = get_db()
    if is_admin_header:
        invoices = conn.execute("SELECT * FROM invoices").fetchall()
    else:
        invoices = conn.execute(
            "SELECT * FROM invoices WHERE owner_id = ?", (session["user_id"],)
        ).fetchall()
    conn.close()

    return jsonify([dict(i) for i in invoices])


@app.route("/invoices/search")
@login_required
def search_invoices():
    q = request.args.get("q", "")

    conn = get_db()
    # VULN D: SQL Injection, string formatting directly into SQL,
    # no parameterization.
    query = f"SELECT * FROM invoices WHERE description LIKE '%{q}%'"
    try:
        results = conn.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        return jsonify({"error": "Query failed", "detail": str(e)}), 400
    conn.close()

    return jsonify([dict(r) for r in results])


@app.route("/ui/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    user = find_user_by_username(username)

    if not user:
        return render_template("login.html", error="User does not exist")
    if user["password"] != password:
        return render_template("login.html", error="Incorrect password")

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    return redirect(url_for("dashboard_page"))


@app.route("/ui/logout", methods=["POST"])
def logout_page():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/ui/dashboard")
@login_required_ui
def dashboard_page():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    invoices = conn.execute("SELECT * FROM invoices WHERE owner_id = ?", (session["user_id"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, invoices=invoices)


@app.route("/ui/invoices/<int:invoice_id>")
@login_required_ui
def invoice_page(invoice_id):
    conn = get_db()
    invoice = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()

    if not invoice:
        flash("Invoice not found")
        return redirect(url_for("dashboard_page"))

    # VULN B (UI variant): same missing ownership check as the API route.
    return render_template("invoice.html", invoice=invoice)


@app.route("/ui/search")
@login_required_ui
def search_page():
    q = request.args.get("q")
    results = None
    error = None

    if q is not None:
        conn = get_db()
        query = f"SELECT * FROM invoices WHERE description LIKE '%{q}%'"
        try:
            results = conn.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            error = f"Query failed: {e}"
        conn.close()

    return render_template("search.html", query=q, results=results, error=error)


@app.route("/ui/posts")
@login_required_ui
def posts_page():
    conn = get_db()
    posts = conn.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("posts.html", posts=posts)


@app.route("/ui/posts/<int:post_id>")
@login_required_ui
def view_post_page(post_id):
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()

    if not post:
        flash("Post not found")
        return redirect(url_for("posts_page"))

    # VULN F (rendering side): view_post.html renders post.content with
    # the |safe filter, disabling Jinja2's automatic HTML escaping.
    return render_template("view_post.html", post=post)


@app.route("/ui/posts/new", methods=["GET", "POST"])
@login_required_ui
def new_post_page():
    if request.method == "GET":
        return render_template("new_post.html", error=None)

    title = request.form.get("title", "")
    content = request.form.get("content", "")

    if not title or not content:
        return render_template("new_post.html", error="Title and content are required")

    image_filename = None
    uploaded_file = request.files.get("image")
    if uploaded_file and uploaded_file.filename:
        # VULN G: Unrestricted File Upload  no extension, content-type,
        # or filename validation. The client-supplied filename is trusted
        # directly, which also opens the door to path traversal.
        image_filename = uploaded_file.filename
        save_path = os.path.join(UPLOAD_FOLDER, image_filename)
        uploaded_file.save(save_path)

    conn = get_db()
    # VULN F (storage side): content is stored exactly as submitted,
    # with no sanitization, the vulnerability is completed at display
    # time in view_post.html.
    conn.execute(
        "INSERT INTO posts (author_id, title, content, image_path) VALUES (?, ?, ?, ?)",
        (session["user_id"], title, content, image_filename)
    )
    conn.commit()
    conn.close()

    flash("Announcement published")
    return redirect(url_for("posts_page"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
