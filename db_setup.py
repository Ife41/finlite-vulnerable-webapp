
"""
Sets up the SQLite database for FinVault (extended FinLite).
Run this once before starting app.py, or whenever you want a fresh reset.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "finlite.db")


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # --- Original FinLite tables (unchanged, referenced by published Semgrep rules) ---

    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer'
        )
    """)

    cur.execute("""
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            description TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            author_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image_path TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    """)

    # --- New FinVault tables ---

    cur.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            account_type TEXT NOT NULL DEFAULT 'Savings',
            balance REAL NOT NULL DEFAULT 0,
            currency TEXT NOT NULL DEFAULT 'USD',
            status TEXT NOT NULL DEFAULT 'active',
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE beneficiaries (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            account_number TEXT NOT NULL,
            bank_name TEXT NOT NULL DEFAULT 'FinVault',
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            account_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Completed',
            reference TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        )
    """)

    cur.execute("""
        CREATE TABLE loans (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            duration_months INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE cards (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            card_number TEXT NOT NULL,
            expiry TEXT NOT NULL DEFAULT '08/29',
            status TEXT NOT NULL DEFAULT 'active',
            spending_limit REAL NOT NULL DEFAULT 1000,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE notifications (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    # --- Seed data ---

    users = [
        (1, "alice", "alice@finlite.local", "alicepass", "customer"),
        (2, "meedah",   "meedah@finlite.local",   "gwen",   "customer"),
        (3, "carol", "carol@finlite.local", "carolpass", "admin"),
    ]
    cur.executemany(
        "INSERT INTO users (id, username, email, password, role) VALUES (?, ?, ?, ?, ?)",
        users
    )

    invoices = [
        (101, 1, 250.00, "Consulting - March"),
        (102, 1, 75.50,  "Consulting - April"),
        (201, 2, 1200.00, "Server hosting - Q1"),
        (202, 2, 60.00,   "Domain renewal"),
    ]
    cur.executemany(
        "INSERT INTO invoices (id, owner_id, amount, description) VALUES (?, ?, ?, ?)",
        invoices
    )

    posts = [
        (1, 3, "Welcome to FinVault", "We're excited to launch our new customer portal. Manage your invoices and account all in one place.", None),
        (2, 3, "Scheduled Maintenance Notice", "Our systems will undergo maintenance this weekend. Some features may be temporarily unavailable.", None),
    ]
    cur.executemany(
        "INSERT INTO posts (id, author_id, title, content, image_path) VALUES (?, ?, ?, ?, ?)",
        posts
    )

    accounts = [
        (1, 1, "100001", "Savings", 5500.00, "USD", "active"),
        (2, 1, "100002", "Current", 1200.00, "USD", "active"),
        (3, 2, "100003", "Savings", 8300.00, "USD", "active"),
        (4, 3, "100004", "Savings", 50000.00, "USD", "active"),
    ]
    cur.executemany(
        "INSERT INTO accounts (id, owner_id, account_number, account_type, balance, currency, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        accounts
    )

    beneficiaries = [
        (1, 1, "John", "100234", "Example Bank"),
        (2, 1, "Mary", "100871", "Example Bank"),
        (3, 2, "Dave", "100555", "Example Bank"),
    ]
    cur.executemany(
        "INSERT INTO beneficiaries (id, owner_id, name, account_number, bank_name) VALUES (?, ?, ?, ?, ?)",
        beneficiaries
    )

    transactions = [
        (1, "Deposit", 2000.00, "Completed", "Initial funding"),
        (1, "Transfer", -500.00, "Completed", "Rent"),
        (3, "Deposit", 8300.00, "Completed", "Initial funding"),
    ]
    cur.executemany(
        "INSERT INTO transactions (account_id, type, amount, status, reference) VALUES (?, ?, ?, ?, ?)",
        transactions
    )

    loans = [
        (1, 1, 5000.00, 12, "Education", "Pending"),
        (2, 2, 10000.00, 24, "Business expansion", "Approved"),
    ]
    cur.executemany(
        "INSERT INTO loans (id, owner_id, amount, duration_months, purpose, status) VALUES (?, ?, ?, ?, ?, ?)",
        loans
    )

    cards = [
        (1, 1, "4111********1234", "08/29", "active", 1000.00),
        (2, 2, "4111********5678", "11/28", "active", 2000.00),
    ]
    cur.executemany(
        "INSERT INTO cards (id, owner_id, card_number, expiry, status, spending_limit) VALUES (?, ?, ?, ?, ?, ?)",
        cards
    )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    init_db()
