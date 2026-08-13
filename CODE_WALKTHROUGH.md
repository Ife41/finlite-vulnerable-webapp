[CODE_WALKTHROUGH.md](https://github.com/user-attachments/files/30997411/CODE_WALKTHROUGH.md)
# Code Walkthrough

This document explains what each file in FinLite does and exactly where each intentional vulnerability lives in the code. It's meant to be read alongside the source, every vulnerability below is marked in the actual code with a `VULN` comment tag at the relevant line.

For exploitation write-ups (commands, screenshots, findings), see [enterprise-homelab-pentest/docs/06-web-exploitation.md](https://github.com/Ife41/enterprise-homelab-pentest/blob/main/docs/06-web-exploitation.md).

---

## `db_setup.py`

A one-time setup script that creates `finlite.db` (SQLite) and seeds it with starting data. Running it again at any point wipes and rebuilds the database from scratch.

**Schema:**

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer'
)
```
Three seeded users: `alice` and `bob` (role `customer`), `carol` (role `admin`).

```sql
CREATE TABLE invoices (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id)
)
```
Four seeded invoices: two owned by Alice (`owner_id: 1`), two by Bob (`owner_id: 2`). This ownership split is what makes the IDOR vulnerability demonstrable: Alice's session can request Bob's invoice IDs directly.

```sql
CREATE TABLE posts (
    id INTEGER PRIMARY KEY,
    author_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    image_path TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id)
)
```
Backs the CMS/announcements feature. `image_path` is nullable (not every post has an image); `created_at` auto-fills via SQLite's `CURRENT_TIMESTAMP` default.

All inserts use parameterized queries (`?` placeholders with a separate values tuple), this file itself contains no injectable SQL.

---

## `app.py`

The entire application: routes, auth, and business logic. Structured as a Flask app with both a small JSON API (`/login`, `/api/register`, `/invoices/...`) and server-rendered HTML pages (everything under `/ui/...`) sharing the same underlying logic.

### Session-based auth

```python
session["user_id"] = user["id"]
session["username"] = user["username"]
session["role"] = user["role"]
```
On successful login, Flask stores these values in a signed cookie sent to the browser. Every subsequent request includes that cookie, and Flask verifies its signature (using `app.secret_key`) before trusting its contents, this is the entire mechanism behind "staying logged in."

### `login_required` / `login_required_ui`

Two decorators gate access to protected routes: the API version returns a `401` JSON error if `session["user_id"]` is missing; the UI version redirects to the login page instead. Applied via `@login_required` / `@login_required_ui` above any route that shouldn't be reachable while logged out.

---

## Vulnerabilities

### VULN A: Broken Authentication (Username Enumeration)
**Location:** `login()` and `login_page()` in `app.py`

```python
if not user:
    return jsonify({"error": "User does not exist"}), 401

if user["password"] != password:
    return jsonify({"error": "Incorrect password"}), 401
```
Two distinct error messages reveal whether a submitted username exists, before password verification occurs. Combined with no rate limiting or account lockout, this enables both username enumeration and unthrottled password brute-forcing.

### VULN B: IDOR (Broken Object Level Authorization)
**Location:** `get_invoice()` and `invoice_page()` in `app.py`

```python
invoice = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
...
return jsonify(dict(invoice))
```
The invoice is fetched purely by ID from the URL, there is no check that `invoice["owner_id"] == session["user_id"]`. Any authenticated user can view any invoice by changing the ID.

### VULN C: IDOR via Trusted Client Header
**Location:** `get_all_invoices()` in `app.py`

```python
is_admin_header = request.headers.get("X-Admin", "false").lower() == "true"
if is_admin_header:
    invoices = conn.execute("SELECT * FROM invoices").fetchall()
```
Admin-level access is granted based on a client-supplied HTTP header rather than the user's actual role stored server-side (`session["role"]`, which is available and safely set at login but never checked here). Headers are fully attacker-controlled and should never function as an authorization signal.

### VULN D: SQL Injection
**Location:** `search_invoices()` and `search_page()` in `app.py`

```python
query = f"SELECT * FROM invoices WHERE description LIKE '%{q}%'"
results = conn.execute(query).fetchall()
```
The search term is inserted directly into the SQL string via an f-string instead of a parameterized query, allowing UNION-based injection and other classic SQL injection techniques.

### VULN E: Mass Assignment
**Location:** `api_register()` in `app.py`

```python
data.get("role", "customer")
```
The registration API accepts and trusts a client-supplied `role` field with no whitelist. The HTML registration form never exposes a role field, but the underlying API it shares logic with does not restrict it, sending `"role": "admin"` directly to the API self-registers an admin account.

### VULN F: Stored XSS
**Location:** `view_post.html`

```jinja
<div>{{ post.content | safe }}</div>
```
Flask/Jinja2 auto-escapes template output by default. The `| safe` filter explicitly disables that protection for post content, which is stored and displayed with no sanitization, any HTML/JavaScript submitted when creating a post executes for every subsequent visitor to that post.

### VULN G: Unrestricted File Upload
**Location:** `new_post_page()` in `app.py`

```python
image_filename = uploaded_file.filename
save_path = os.path.join(UPLOAD_FOLDER, image_filename)
uploaded_file.save(save_path)
```
No validation on file extension, content type, or file contents. The client-supplied filename is trusted and used directly, which also creates a path traversal risk if a crafted filename is submitted.

---

## A known gap (not yet formally classified)

`new_post_page()` is protected only by `@login_required_ui`  it never checks `session["role"] == "admin"`. The "+ New Announcement" button is hidden from non-admin users in `posts.html`, but the route itself enforces nothing, meaning any authenticated customer who knows the URL can still create posts. This is a good illustration of a common real-world mistake: hiding a UI element is not the same as enforcing access control server-side.

---

## Design choices worth noting

- **Passwords are stored in plain text.** Not a deliberate vulnerability lesson in this version of the app, a simplification to keep focus on the vulnerabilities actually being studied. In a real security review this would itself be a critical finding.
- **`debug=True`** is enabled in `app.run()`. Convenient for local development (auto-reload, detailed tracebacks) but a genuine risk in any real deployment, since Flask's debug mode can expose source code and, in some configurations, allow arbitrary code execution via its interactive debugger.
