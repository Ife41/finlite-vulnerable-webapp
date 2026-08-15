# FinLite: Intentionally Vulnerable Fintech-Style Web App

FinLite is a small, self-built web application designed to practice and document Application Security testing. It simulates a fintech-style organization portal, user accounts, invoices, and a company announcements CMS, with a set of intentional, clearly documented vulnerabilities.

This project was built after noticing **IDOR (Insecure Direct Object Reference)** as one of the most common real-world vulnerabilities in financial applications, and I took up the challenge towards finding a practical way to catch it before deployment rather than after.

> ⚠️ **This application is intentionally insecure.** Run it only in an isolated local environment. 

---

## Why this project exists

- **Practical AppSec skill-building**  designing an app *and* attacking it builds a fuller understanding of vulnerabilities than either alone.
- **A realistic target for a build-time IDOR detection tool**  a related project (Semgrep rule + CI/CD pipeline) uses this app's known-vulnerable endpoints as its test case. See [finlite-idor-detection](https://github.com/Ife41/finlite-idor-detection)
- **A documented exploitation target** the actual attack write-up against this app lives in a separate repo: [enterprise-homelab-pentest](https://github.com/Ife41/enterprise-homelab-pentest/blob/main/docs/06-web-exploitation.md)

---

## Architecture

- **Backend:** Python 3, Flask
- **Database:** SQLite (single-file, no separate DB server required)
- **Frontend:** Server-rendered HTML (Jinja2 templates), plain CSS, no JS framework
- **Auth:** Session-based (Flask's built-in signed cookie sessions)

```
finlite-app/
├── app.py                 # All routes and application logic
├── db_setup.py             # Creates and seeds the SQLite database
├── requirements.txt
├── templates/
│   ├── base.html            # Shared layout, nav bar
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── invoice.html
│   ├── search.html
│   ├── posts.html            # Announcements list (CMS)
│   ├── view_post.html        # Single announcement view
│   └── new_post.html         # Create announcement form
└── static/
    ├── style.css
    └── uploads/               # User-uploaded post images land here
```

## Data model

**users**  id, username, email, password, role (`customer` / `admin`)
**invoices**  id, owner_id, amount, description
**posts**  id, author_id, title, content, image_path, created_at

## Seeded accounts

| Username | Password | Role |
|---|---|---|
| alice | alicepass | customer |
| bob | bobpass | customer |
| carol | carolpass | admin |

---

## Setup

```bash
git clone https://github.com/Ife41/finlite-vulnerable-webapp.git
cd finlite-vulnerable-webapp
pip3 install -r requirements.txt --break-system-packages
python3 db_setup.py
python3 app.py
```

The app runs at `http://127.0.0.1:5000`. Web UI starts at `/ui/login`.

Re-running `python3 db_setup.py` at any point wipes and rebuilds the database with fresh seed data, useful for resetting after testing.

---

## Vulnerability Index

Each vulnerability is marked in `app.py` with a `VULN` comment tag at the relevant code location.

| ID | Class | Location | Status |
|---|---|---|---|
| A | Broken Authentication (username enumeration, no rate limiting) | `/login`, `/ui/login` | ✅ Implemented |
| B | IDOR / Broken Object Level Authorization | `/invoices/<id>` | ✅ Implemented |
| C | IDOR via trusted client header | `/invoices/all` | ✅ Implemented |
| D | SQL Injection | `/invoices/search` | ✅ Implemented |
| E | Mass Assignment | `/api/register` | ✅ Implemented |
| F | Stored XSS | Announcement post content (`view_post.html`) | ✅ Implemented |
| G | Unrestricted File Upload | Announcement image upload (`/ui/posts/new`) | ✅ Implemented |


Detailed exploitation write-ups (commands, screenshots, findings) for each vulnerability are documented separately in [enterprise-homelab-pentest/docs/06-web-exploitation.md](https://github.com/Ife41/enterprise-homelab-pentest/blob/main/docs/06-web-exploitation.md).

---

## A note on design choices

A couple of deliberate decisions worth explaining rather than leaving as apparent oversights:

- **Passwords are stored in plain text.** This wasn't built as a specific "weak password storage" vulnerability lesson, it's a simplification to keep focus on the vulnerabilities actually being studied (IDOR, injection, etc.). In a real audit, this would itself be a critical finding (missing password hashing).
- **`debug=True` is enabled in `app.py`.** Convenient for local development (auto-reload, detailed error pages), but a genuine security risk in any real deployment, never used in production.

## Roadmap

- [ ] Reflected XSS, DOM XSS, hidden endpoint, API documentation-based exploitation
- [ ] Customer support LLM feature with associated LLM-specific vulnerabilities
- [ ] Deployment to a Windows Server / IIS environment (via `httpplatformhandler`), as part of the broader [enterprise-homelab-pentest](https://github.com/Ife41/enterprise-homelab-pentest) project
- [ ] Fixed/patched version of each endpoint, for before/after comparison with the IDOR detection tool
