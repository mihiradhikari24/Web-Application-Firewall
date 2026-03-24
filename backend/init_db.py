import sqlite3
import os

# ─────────────────────────────
# Absolute DB path (IMPORTANT)
# ─────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")


def init_db():
    """Recreate database from scratch every time"""

    # 🔥 DELETE OLD DB FILE (correct path)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()

    # ─────────────────────────────
    # CREATE TABLES
    # ─────────────────────────────
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT,
            body TEXT
        )
    """)

    # ─────────────────────────────
    # INSERT FIXED DATA
    # ─────────────────────────────
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
    cursor.execute("INSERT INTO users VALUES (2, 'alice', 'pass456')")

    cursor.execute("INSERT INTO comments VALUES (1, 'bob', 'Hello world!')")

    conn.commit()
    return conn

if __name__ == "__main__":
    init_db()
    print(f"✅ Database created at: {DB_PATH}")