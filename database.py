"""
Bot database layer - uses SQLite (file, no need for a separate server).

Tables:
- users: basic information about each user (number of messages, number of spam, whitelist status)
- flagged_messages: archive of messages that were detected as suspicious/spam (for later review)

Note: for simplicity, each function opens and closes a new connection.
For a bot with very high traffic, it is better to use a connection pool,
but for this project (few groups, normal traffic) this method is quite sufficient.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "antispam.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the tables if they do not exist. It must be called once when the robot starts."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            first_name TEXT,
            first_seen TEXT,
            message_count INTEGER DEFAULT 0,
            spam_count INTEGER DEFAULT 0,
            is_whitelisted INTEGER DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS flagged_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            chat_id INTEGER,
            chat_title TEXT,
            message_text TEXT,
            score INTEGER,
            reasons TEXT,
            action TEXT,
            timestamp TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def touch_user(user_id: int, first_name: str):
    """If the user is new, it registers them, otherwise it increases their message counter by one."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    exists = cur.fetchone()

    if exists is None:
        cur.execute(
            """INSERT INTO users (user_id, first_name, first_seen, message_count)
               VALUES (?, ?, ?, 1)""",
            (user_id, first_name, datetime.now(timezone.utc).isoformat()),
        )
    else:
        cur.execute(
            "UPDATE users SET message_count = message_count + 1, first_name = ? WHERE user_id = ?",
            (first_name, user_id),
        )

    conn.commit()
    conn.close()


def is_whitelisted(user_id: int) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_whitelisted FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return bool(row["is_whitelisted"]) if row else False


def set_whitelisted(user_id: int, value: bool = True):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_whitelisted = ? WHERE user_id = ?",
        (1 if value else 0, user_id),
    )
    conn.commit()
    conn.close()


def increment_spam_count(user_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET spam_count = spam_count + 1 WHERE user_id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()


def get_user_stats(user_id: int) -> dict | None:
    """Returns the registered information of a user, or None if not found."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def log_flagged_message(
    user_id: int,
    chat_id: int,
    chat_title: str,
    message_text: str,
    score: int,
    reasons: list[str],
    action: str,
):
    """Saves a suspicious/spam message to the archive (for later review by the admin)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO flagged_messages
           (user_id, chat_id, chat_title, message_text, score, reasons, action, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id,
            chat_id,
            chat_title,
            message_text,
            score,
            "، ".join(reasons),
            action,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()
