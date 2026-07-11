"""
ماژول تشخیص جوین دسته‌جمعی مشکوک (Flood Join Detector).

وقتی چند عضو جدید توی یه بازه‌ی زمانی کوتاه با هم به گروه اضافه بشن،
معمولاً نشونه‌ی حمله‌ی اسپم/بات‌های تبلیغاتیه. این ماژول دو کار می‌کنه:

1. زمان جوین هر عضو جدید رو (به تفکیک گروه) ثبت می‌کنه و اگه تعداد
   جوین‌ها توی یه بازه از حد مجاز رد بشه، هشدار می‌ده.
2. زمان جوین هر کاربر رو جدا نگه می‌داره تا اگه بلافاصله بعد از
   جوین‌شدن پیام مشکوکی فرستاد، امتیاز اضافه‌تری بگیره.
"""

from collections import defaultdict, deque
from time import time

# ---------------------------------------------------------------------------
# تنظیمات قابل ویرایش
# ---------------------------------------------------------------------------

FLOOD_JOIN_COUNT = 4  # این تعداد جوین...
FLOOD_JOIN_WINDOW_SECONDS = 60  # ...توی این بازه (ثانیه) => مشکوک

NEW_USER_GRACE_SECONDS = 300  # ۵ دقیقه‌ی اول بعد از جوین، کاربر "تازه‌وارد" حساب می‌شه
NEW_USER_BONUS_SCORE = 20  # اگه تازه‌وارد پیام از قبل مشکوکی بفرسته، این امتیاز اضافه می‌شه

# ---------------------------------------------------------------------------

# جوین‌های اخیر هر گروه: {chat_id: deque[timestamp, ...]}
_chat_joins: dict[int, deque] = defaultdict(lambda: deque(maxlen=FLOOD_JOIN_COUNT * 3))

# زمان جوین هر کاربر: {user_id: timestamp}
_user_join_time: dict[int, float] = {}


def record_join(chat_id: int, user_id: int) -> dict:
    """
    وقتی یه عضو جدید وارد گروه می‌شه صدا زده می‌شه.

    خروجی:
        {"is_flood": bool, "recent_join_count": int}
    """
    now = time()
    _user_join_time[user_id] = now

    joins = _chat_joins[chat_id]
    joins.append(now)

    while joins and now - joins[0] > FLOOD_JOIN_WINDOW_SECONDS:
        joins.popleft()

    recent_count = len(joins)
    return {
        "is_flood": recent_count >= FLOOD_JOIN_COUNT,
        "recent_join_count": recent_count,
    }


def get_new_user_bonus(user_id: int) -> int:
    """اگه کاربر هنوز توی بازه‌ی «تازه‌وارد»‌ باشه، امتیاز بونوس رو برمی‌گردونه، وگرنه صفر."""
    join_time = _user_join_time.get(user_id)
    if join_time is None:
        return 0  # زمان جوینش رو ندیدیم (مثلاً قبل از استارت ربات عضو شده)

    if time() - join_time <= NEW_USER_GRACE_SECONDS:
        return NEW_USER_BONUS_SCORE

    return 0
