"""
اسکریپت کوچیک برای دیدن محتوای دیتابیس ربات توی ترمینال.
این فایل رو کنار bot.py بذار و اجرا کن:
    python view_db.py
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "antispam.db"


def print_table(cur, table_name, columns):
    print(f"\n{'=' * 60}")
    print(f"  جدول: {table_name}")
    print(f"{'=' * 60}")

    cur.execute(f"SELECT * FROM {table_name}")
    rows = cur.fetchall()

    if not rows:
        print("  (خالیه - هنوز رکوردی ثبت نشده)")
        return

    for row in rows:
        print("-" * 60)
        for col in columns:
            print(f"  {col}: {row[col]}")


def main():
    if not DB_PATH.exists():
        print(f"فایل دیتابیس پیدا نشد: {DB_PATH}")
        print("احتمالاً هنوز ربات رو اجرا نکردی یا هنوز پیامی رد و بدل نشده.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print_table(
        cur,
        "users",
        [
            "user_id",
            "first_name",
            "first_seen",
            "message_count",
            "spam_count",
            "is_whitelisted",
        ],
    )

    print_table(
        cur,
        "flagged_messages",
        [
            "id",
            "user_id",
            "chat_title",
            "message_text",
            "score",
            "reasons",
            "action",
            "timestamp",
        ],
    )

    conn.close()
    print(f"\n{'=' * 60}\n")


if __name__ == "__main__":
    main()
