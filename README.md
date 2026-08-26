# FinVault

A deliberately vulnerable banking web application, built for hands-on application security practice. FinVault started as a small proof-of-concept called FinLite (7 vulnerabilities) and grew into a full banking feature set with 18 documented vulnerabilities spanning access control, injection, business logic, and AI-specific risks.

This repo is meant to be exploited, not deployed. Every vulnerability listed below was added intentionally, for training and demonstration purposes, unless explicitly marked as a fixed bug.

---

## About the project

FinVault simulates a retail banking platform: account management, money transfers, beneficiaries, transaction history, deposits, virtual cards, loans, notifications, an admin panel, and an internal account verification service. The goal is to give AppSec learners (and reviewers, like the SAST rules in the companion repo) a realistic, multi-feature target rather than a single isolated bug.

The app has gone through two phases:
- **FinLite**: the original, smaller Flask/SQLite proof-of-concept covering vulnerabilities A through G.
- **FinVault**: the expanded version, adding full banking functionality and eleven additional vulnerabilities (H through R), based on a feature spec covering the areas above.

## Tech stack

- Python / Flask
- SQLite
- Server-rendered HTML templates, redesigned with a sidebar navigation layout and a banking-themed color palette (deep forest green, ink black, muted gold accent)
- A local LLM (via Ollama, `llama3.2`) powers an in-app AI assistant used for one of the vulnerability scenarios

## Features

- Account overview with masked account numbers and a balance summary
- Transfers between accounts, including beneficiary management
- Transaction history
- Deposits
- Virtual card issuance and card detail viewing
- Loan applications, with an admin approval flow
- Notifications
- An admin panel for account and loan management
- An internal account verification service
- An AI chatbot assistant with tool-calling ability, used to explore excessive agency risk in LLM-integrated features

## Vulnerabilities

FinVault currently ships with 18 intentional vulnerabilities, labeled A through R. Categories only are listed here; exact routes, payloads, and reproduction steps are intentionally not included in this README so the app stays useful as a hands-on exercise.

| ID | Category |
|----|----------|
| A | Broken authentication (username enumeration) |
| B | IDOR (invoices) |
| C | IDOR via trusted client header |
| D | SQL injection (invoice search) |
| E | Mass assignment (registration role field) |
| F | Stored XSS (announcements) |
| G | Unrestricted file upload |
| H | IDOR (account details) |
| I | IDOR (transfer source account, money movement) |
| J | Business logic flaw (no balance check on transfer) |
| K | Stored XSS (beneficiary name) |
| L | IDOR (beneficiary deletion) |
| M | IDOR (transaction history via query parameter) |
| N | SSRF (account verification endpoint) |
| O | IDOR (card details, sensitive data exposure) |
| P | Mass assignment (loan status field) |
| Q | Broken access control (admin panel) |
| R | AI chatbot: excessive agency / prompt injection (loan approval) |

Some of these are deliberately harder than others. A few require noticing something beyond straightforward URL guessing.

## Vulnerability scoreboard

FinVault includes a scoreboard that tracks which vulnerabilities have been found and solved during a session, with difficulty ratings and hints. It's not linked anywhere in the app's navigation, so finding it is part of the exercise.

## AI chatbot feature

One of the newer additions is an in-app assistant that can take action on the user's behalf, including approving loans. It's a practical way to explore what can go wrong when an LLM is given tool access without proper server-side authorization checks. The chatbot runs against a local Ollama model rather than a hosted API.

## Known bugs (not vulnerabilities)

Two issues were identified and fixed during development that were genuine bugs rather than intended behavior:
- Approving a loan didn't originally credit the applicant's balance or log a transaction. This is fixed. Approvals now update the balance and create a transaction record.
- The chatbot occasionally hallucinated loan IDs that didn't exist, including in response to plain greetings. This is fixed. The assistant is now grounded with the real list of pending loans on every turn and only calls tools when there's an actual match.

## Setup

```bash
git clone https://github.com/Ife41/finlite-vulnerable-webapp.git
cd finlite-vulnerable-webapp
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

The app runs on Flask's default local server. Check `app.py` for the port and any environment variables (such as the Ollama endpoint) before starting.

> This application is intentionally insecure. Run it locally, in an isolated environment. Do not expose it to the public internet or deploy it anywhere reachable outside a lab setting.

## Related repos

- [`sast-idor-bola-detection`]([https://github.com/Ife41/finlite-idor-detection]): custom Semgrep rules and a CI pipeline built to catch the IDOR and header-based authorization bypass patterns used in this app.
- `enterprise-homelab-pentest`: a self-built Windows Server lab used to practice exploiting FinVault from an external attacker's perspective, including web exploitation and SMB/FTP/SSH service attacks.

## Disclaimer

FinVault is built strictly for educational and authorized security testing purposes. Do not use any part of this code, or the techniques it demonstrates, against systems you don't own or have explicit permission to test.
