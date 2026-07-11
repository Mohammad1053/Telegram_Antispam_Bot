"""
ماژول بررسی لینک با سرویس خارجی Google Safe Browsing API.

لینک‌های داخل یه پیام رو استخراج می‌کنه و از سرویس گوگل می‌پرسه که آیا
این‌ها روی لیست سایت‌های مخرب/فیشینگ گوگل هستن یا نه.

نیاز به یه API Key رایگان از Google Cloud Console داره (رایگانه، توضیحش
توی README پروژه هست). اگه API Key تنظیم نشده باشه، این ماژول فقط
هیچ‌کاری نمی‌کنه (fail-open) - بقیه‌ی ربات بدون این قابلیت هم کار می‌کنه.

نکته درباره‌ی نسخه‌ی API: از Lookup API نسخه‌ی v4 استفاده می‌کنیم. با
اینکه گوگل این نسخه رو "منسوخ" (deprecated) اعلام کرده و در حال مهاجرت
به نسخه‌ی v5 هست، v4 هنوز کاملاً فعال، پایدار و به‌خوبی مستندسازی‌شده‌ست.
نسخه‌ی جایگزین (v5alpha1) هنوز آزمایشیه و در عمل رفتار غیرقابل‌اعتمادی
از خودش نشون داد - برای همین فعلاً v4 انتخاب مطمئن‌تریه.

نکته‌ی دیگه: اگه خود سرویس گوگل در دسترس نبود یا خطا داد، به‌جای اینکه
ربات رو متوقف کنیم، فقط نادیده می‌گیریم (fail-open) - چون این یه لایه‌ی
اضافه‌ست، نه بخش اصلی تشخیص اسپم.
"""

import logging
import re

import httpx

logger = logging.getLogger(__name__)

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

URL_EXTRACT_PATTERN = re.compile(
    r"(https?://[^\s]+)|(www\.[^\s]+)",
    re.IGNORECASE,
)

RULE_WEIGHT = 100  # اگه گوگل تأیید کنه لینک مخربه، به‌تنهایی از آستانه‌ی حذف رد می‌شه

CLIENT_ID = "antispam-telegram-bot"
CLIENT_VERSION = "1.0"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def extract_urls(text: str) -> list[str]:
    """لینک‌های داخل یه متن رو استخراج می‌کنه."""
    matches = URL_EXTRACT_PATTERN.findall(text)
    return [http_match or www_match for http_match, www_match in matches if http_match or www_match]


async def check_urls(urls: list[str], api_key: str | None) -> dict:
    """
    لیستی از لینک‌ها رو در یه درخواست به گوگل می‌ده و چک می‌کنه که آیا مخرب‌ان یا نه.

    خروجی:
        {
            "is_malicious": bool,
            "matched_urls": [str, ...],  # لینک‌هایی که مخرب تشخیص داده شدن
            "score": int,
        }
    """
    if not api_key or not urls:
        return {"is_malicious": False, "matched_urls": [], "score": 0}

    request_body = {
        "client": {"clientId": CLIENT_ID, "clientVersion": CLIENT_VERSION},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                SAFE_BROWSING_ENDPOINT,
                params={"key": api_key},
                json=request_body,
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as e:
        logger.warning(f"بررسی لینک با Safe Browsing ناموفق بود، نادیده گرفته شد: {e}")
        return {"is_malicious": False, "matched_urls": [], "score": 0}

    matches = data.get("matches", [])
    matched_urls = sorted(
        {m["threat"]["url"] for m in matches if "threat" in m and "url" in m["threat"]}
    )

    return {
        "is_malicious": bool(matched_urls),
        "matched_urls": matched_urls,
        "score": RULE_WEIGHT if matched_urls else 0,
    }
