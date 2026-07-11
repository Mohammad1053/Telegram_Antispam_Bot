"""
ماژول تشخیص اسپم مبتنی بر قانون (Rule-Based).

این نسخه سه تا سیگنال رو چک می‌کنه:
1. وجود کلمات/عبارات ممنوعه (تبلیغاتی، اسپم رایج)
2. وجود لینک (http, www, t.me, @username تبلیغاتی)
3. نسبت حروف بزرگ بیش‌ازحد (فریاد زدن / جلب توجه)

در روزهای بعد، این تابع‌ها به یه سیستم امتیازدهی (به‌جای تصمیم قطعی)
و ذخیره‌سازی در دیتابیس تبدیل می‌شن.
"""

import re

# ---------------------------------------------------------------------------
# تنظیمات قابل ویرایش - این‌ها رو با توجه به نیاز گروه خودت تغییر بده
# ---------------------------------------------------------------------------

BANNED_WORDS = [
    "فالوور رایگان",
    "خرید فالوور",
    "بازدید ارزان",
    "سکه رایگان",
    "کسب درآمد میلیونی",
    "سرمایه گذاری تضمینی",
    "فروش دنبال کننده",
    "cheap followers",
    "free followers",
    "make money fast",
    "guaranteed profit",
]

CAPS_RATIO_THRESHOLD = 0.6  # اگه ۶۰٪ یا بیشتر حروف پیام بزرگ بود، مشکوکه
MIN_LENGTH_FOR_CAPS_CHECK = 10  # پیام‌های کوتاه (مثل "OK") رو چک نکن

# لینک: http/https, www., t.me/xxx, telegram.me/xxx
URL_PATTERN = re.compile(
    r"(https?://\S+)|(www\.\S+)|(t\.me/\S+)|(telegram\.me/\S+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# سیستم امتیازدهی
# هر قانون یه وزن داره؛ مجموع امتیازها تعیین می‌کنه چه اتفاقی بیفته.
# این اعداد رو با توجه به تجربه‌ی واقعی گروهت می‌تونی تنظیم کنی.
# ---------------------------------------------------------------------------

RULE_WEIGHTS = {
    "banned_word": 60,  # به‌تنهایی از حد حذف رد می‌شه
    "link": 40,  # به‌تنهایی فقط هشدار می‌ده، حذف نمی‌شه
    "excessive_caps": 30,
}

SPAM_DELETE_THRESHOLD = 50  # امتیاز مساوی یا بیشتر از این => حذف پیام
SPAM_WARN_THRESHOLD = 25  # امتیاز بین این و آستانه‌ی حذف => فقط لاگ هشدار

# ---------------------------------------------------------------------------


def contains_banned_word(text: str) -> str | None:
    """اگه متن شامل یکی از کلمات ممنوعه بود، همون کلمه رو برمی‌گردونه، وگرنه None."""
    lowered = text.lower()
    for word in BANNED_WORDS:
        if word.lower() in lowered:
            return word
    return None


def contains_link(text: str) -> bool:
    """آیا متن شامل لینک هست؟"""
    return bool(URL_PATTERN.search(text))


def has_excessive_caps(text: str) -> bool:
    """آیا نسبت حروف بزرگ به کل حروف بیش از حد مجازه؟"""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < MIN_LENGTH_FOR_CAPS_CHECK:
        return False
    upper_count = sum(1 for c in letters if c.isupper())
    ratio = upper_count / len(letters)
    return ratio >= CAPS_RATIO_THRESHOLD


def analyze_message(text: str) -> dict:
    """
    متن پیام رو تحلیل و امتیازدهی می‌کنه.

    خروجی:
        {
            "score": int,           # مجموع امتیاز مشکوک‌بودن
            "reasons": [str, ...],  # دلایل به‌همراه امتیاز هرکدوم
            "is_spam": bool,        # آیا از آستانه‌ی حذف رد شده؟
        }
    """
    score = 0
    reasons = []

    banned = contains_banned_word(text)
    if banned:
        weight = RULE_WEIGHTS["banned_word"]
        score += weight
        reasons.append(f'کلمه‌ی ممنوعه: "{banned}" (+{weight})')

    if contains_link(text):
        weight = RULE_WEIGHTS["link"]
        score += weight
        reasons.append(f"شامل لینک (+{weight})")

    if has_excessive_caps(text):
        weight = RULE_WEIGHTS["excessive_caps"]
        score += weight
        reasons.append(f"حروف بزرگ بیش‌ازحد (+{weight})")

    return {
        "score": score,
        "reasons": reasons,
        "is_spam": score >= SPAM_DELETE_THRESHOLD,
    }
