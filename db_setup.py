import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "finlite.db")


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

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

    users = [
        (1, "alice", "alice@finlite.local", "alicepass", "customer"),
        (2, "bob",   "bob@finlite.local",   "bobpass",   "customer"),
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
        (1, 3, "Welcome to FinLite", "We're excited to launch our new customer portal. Manage your invoices and account all in one place.", None),
        (2, 3, "Scheduled Maintenance Notice", "Our systems will undergo maintenance this weekend. Some features may be temporarily unavailable.", None),
    ]
    cur.executemany(
        "INSERT INTO posts (id, author_id, title, content, image_path) VALUES (?, ?, ?, ?, ?)",
        posts
    )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    init_db()
