"""
ماژول تشخیص پیام تکراری (Flood / Repeated Message Detector).

برخلاف spam_detector.py که فقط به متن *یه* پیام نگاه می‌کنه، این ماژول
تاریخچه‌ی چند پیام آخر هر کاربر رو (فقط توی حافظه، نه دیتابیس - چون فقط
برای مقایسه‌ی کوتاه‌مدت لازمه) نگه می‌داره و اگه کاربر پشت‌سرهم پیام
یکسان یا خیلی شبیه به‌هم بفرسته (کپی‌پیست تبلیغاتی رایج)، تشخیصش می‌ده.
"""

from collections import defaultdict, deque
from difflib import SequenceMatcher
from time import time

# ---------------------------------------------------------------------------
# تنظیمات قابل ویرایش
# ---------------------------------------------------------------------------

HISTORY_SIZE = 5  # چند تا پیام آخر هر کاربر رو نگه داریم
TIME_WINDOW_SECONDS = 60  # پیام‌های قدیمی‌تر از این چند ثانیه، دیگه حساب نمی‌شن
SIMILARITY_THRESHOLD = 0.9  # شباهت بالاتر از این یعنی "همون پیام" (۰ تا ۱)
REPEAT_COUNT_THRESHOLD = 3  # این تعداد تکرار مشابه => اسپم محسوب می‌شه
RULE_WEIGHT = 70  # امتیازی که این قانون به مجموع امتیاز اضافه می‌کنه

# ---------------------------------------------------------------------------

# تاریخچه‌ی هر کاربر: {user_id: deque[(timestamp, normalized_text), ...]}
_user_history: dict[int, deque] = defaultdict(lambda: deque(maxlen=HISTORY_SIZE))


def _normalize(text: str) -> str:
    """فاصله‌های اضافه و بزرگ/کوچیکی حروف رو نادیده می‌گیره تا مقایسه دقیق‌تر بشه."""
    return " ".join(text.strip().lower().split())


def _is_similar(a: str, b: str) -> bool:
    if a == b:
        return True
    return SequenceMatcher(None, a, b).ratio() >= SIMILARITY_THRESHOLD


def check_repetition(user_id: int, text: str) -> dict:
    """
    پیام جدید یه کاربر رو با تاریخچه‌ی پیام‌های اخیرش مقایسه می‌کنه.

    خروجی:
        {
            "is_repeated": bool,   # آیا از حد تکرار مجاز رد شده؟
            "repeat_count": int,   # این پیام چندمین‌بار مشابه (شامل خودش)؟
            "score": int,          # امتیازی که باید به مجموع اضافه بشه
        }
    """
    now = time()
    normalized = _normalize(text)
    history = _user_history[user_id]

    # پیام‌های خارج از بازه‌ی زمانی رو دور بریز
    while history and now - history[0][0] > TIME_WINDOW_SECONDS:
        history.popleft()

    similar_count = sum(
        1 for _, old_text in history if _is_similar(normalized, old_text)
    )

    history.append((now, normalized))

    repeat_count = similar_count + 1  # +۱ یعنی خودِ همین پیام
    is_repeated = repeat_count >= REPEAT_COUNT_THRESHOLD

    return {
        "is_repeated": is_repeated,
        "repeat_count": repeat_count,
        "score": RULE_WEIGHT if is_repeated else 0,
    }
