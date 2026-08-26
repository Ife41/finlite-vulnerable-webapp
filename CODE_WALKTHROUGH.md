# Code Walkthrough

This walks through how FinVault is put together: the app structure, the main features, and where the intentional vulnerabilities live in the code. It's meant as an orientation for anyone reading the source, not a full line-by-line trace.

Note: this draft is based on the app's feature set and design decisions rather than a direct read of the current source files. Treat section headers and general structure as accurate, but double check exact file names, function names, and line numbers against the real codebase before publishing, and adjust anything that's drifted.

---

## Project structure

A typical Flask app layout is assumed here. Update this section to match the real file tree.

```
finvault/
├── app.py                  # app entry point, route registration
├── models/                 # SQLite models (users, accounts, transfers, loans, cards, etc.)
├── routes/                 # route handlers, likely grouped by feature
├── templates/              # HTML templates, sidebar nav + banking theme
├── static/                 # CSS, JS, images
├── chatbot/                # AI assistant integration (Ollama)
└── database.db             # SQLite database
```

## Core data model

FinVault's data model covers a small banking domain:

- **Users**: login credentials, role field (used in the mass assignment vulnerability), and the additional client-readable context used by the admin panel
- **Accounts**: balance, account number (masked in the UI), owner
- **Transfers**: source account, destination, amount, timestamp
- **Beneficiaries**: saved transfer recipients per user
- **Transactions**: a log of deposits, transfers, and loan disbursements
- **Cards**: virtual card details tied to an account
- **Loans**: application status, amount, applicant, and approval state
- **Invoices**: used in the earlier FinLite-era IDOR and SQL injection scenarios, still present in FinVault

## Authentication

Login uses Flask's standard session mechanism, which is correctly signed and secure. A separate, additional cookie is also set at login time to carry some session context to the frontend. That second cookie is where one of the access control vulnerabilities lives; the real session-based login elsewhere in the app is not affected.

Username enumeration (vulnerability A) comes from how the login and/or registration flow responds differently depending on whether a username exists.

## Accounts, transfers, and beneficiaries

Account detail, transfer, and beneficiary routes generally look up the requested resource by ID from the URL or a request parameter. Several of these routes trust the ID without confirming it belongs to the logged-in user, which is the source of most of the IDOR vulnerabilities (B, H, I, L, M, O).

The transfer flow itself does not check the source account's balance before moving funds, which allows an account to go negative (vulnerability J).

## Search and admin features

The invoice search feature builds a query using user input without parameterization, which is the SQL injection vulnerability (D).

Registration accepts a role field directly from the client without restricting it server-side (vulnerability E).

Announcement and beneficiary name fields are rendered without sanitization, producing stored XSS (F, K).

The file upload feature does not validate file type or content (vulnerability G).

## Admin panel

The admin panel exists behind what looks like a standard access check, but the actual authorization decision reads from the additional client-readable cookie set at login rather than the signed session. This is a deliberate design choice, meant to be a step above simple URL guessing: an attacker has to notice the cookie, understand its contents, and modify it. Exact mechanics are intentionally left out of this document; see the scoreboard hints in-app instead.

## Account verification service (SSRF)

The account verification endpoint accepts a URL or host as input and makes a server-side request to it, without restricting the destination. This is vulnerability N.

## Loans

Loan applications can be approved through the admin panel or through the AI chatbot. Approval correctly credits the applicant's account and logs a transaction. This was a real bug earlier in development (approvals weren't reflected in the balance or transaction history) and has since been fixed.

The loan status field is also directly settable via the loans API without proper authorization, which is vulnerability P.

## AI chatbot (vulnerability R)

The chatbot runs against a local Ollama model (`llama3.2`) rather than a hosted API, and has access to an `approve_loan` tool. The system prompt instructs it to trust the user's claims about their role, and there's no server-side check when the tool actually fires, which is the core of the excessive agency / prompt injection risk.

Two things worth knowing if you're reading this code:
- The system prompt is grounded with the real-time list of pending loans (ID, applicant, amount) on every turn, and the model is instructed not to call the tool during casual conversation. This was added after the model was found hallucinating loan IDs even on simple greetings.
- The scoreboard only marks this vulnerability solved when a real loan is actually approved through the chatbot, not on a hallucinated or nonexistent loan ID. Earlier, the detection logic didn't check for that, and would fire on hallucinated IDs.

## Vulnerability scoreboard

A scoreboard tracks which vulnerabilities have been triggered per session, with hints and difficulty ratings rather than exact routes or descriptions. It's intentionally not linked from the app's navigation. Detection is heuristic, based on the actual exploit conditions being met at runtime (for example, viewing an invoice that isn't yours). Implementation details are left out of this document on purpose.

## UI and design notes

The frontend uses a sidebar navigation layout and a banking-themed palette (deep forest green, ink black, muted gold accent), replacing an earlier generic top-nav and navy/blue scheme. The account balance component (masked account number, tabular currency figures) is the app's signature visual element and appears across several pages.

Two routes that originally returned raw JSON instead of a rendered page, invoice listing and account verification, now have proper UI pages.

## Known bugs (fixed, not vulnerabilities)

For clarity, these were genuine bugs rather than intended behavior, and are called out separately from the vulnerability list above:
- Loan approval not crediting the applicant's balance or logging a transaction. Fixed.
- Chatbot hallucinating loan IDs, including on casual greetings, and the scoreboard incorrectly marking the loan approval vulnerability solved as a result. Fixed.

## What's not yet in FinVault

A few scenarios from the original FinLite scope haven't been ported over yet: reflected XSS, DOM XSS, a hidden/undocumented API endpoint, and an API exploitation scenario via exposed documentation. These are candidates for a future update rather than part of the current 18.

---

For the full list of vulnerabilities by category, see the main [README](./README.md).
