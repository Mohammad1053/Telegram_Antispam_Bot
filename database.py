"""
لایه‌ی دیتابیس ربات - از SQLite استفاده می‌کنه (فایلی، بدون نیاز به سرور جدا).

جدول‌ها:
- users: اطلاعات پایه‌ی هر کاربر (تعداد پیام، تعداد اسپم، وضعیت سفیدلیست)
- flagged_messages: آرشیو پیام‌هایی که مشکوک/اسپم تشخیص داده شدن (برای بازبینی بعدی)

نکته: برای سادگی، هر تابع یه اتصال جدید باز و بسته می‌کنه.
برای یه ربات با ترافیک خیلی بالا بهتره از connection pool استفاده بشه،
ولی برای این پروژه (چند گروه، ترافیک معمولی) این روش کاملاً کافیه.
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
    """جدول‌ها رو اگه وجود نداشته باشن می‌سازه. باید یه‌بار موقع استارت ربات صدا زده بشه."""
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
    """اگه کاربر تازه‌ست ثبتش می‌کنه، وگرنه شمارنده‌ی پیامش رو یکی زیاد می‌کنه."""
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
    """اطلاعات ثبت‌شده‌ی یه کاربر رو برمی‌گردونه، یا None اگه پیدا نشد."""
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
    """یه پیام مشکوک/اسپم رو توی آرشیو ذخیره می‌کنه (برای بازبینی بعدی توسط ادمین)."""
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
