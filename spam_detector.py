"""
Rule-Based Spam Detection Module.

This version checks for three signals:
1. Presence of banned words/phrases (promotional, common spam)
2. Presence of links (http, www, t.me, @username promotional)
3. Excessive capitalization (shouting/attention-grabbing)

In the coming days, these functions will be transformed into a scoring system (instead of a definitive decision)
and stored in the database.
"""

import re

# ---------------------------------------------------------------------------
# Editable settings - change these to suit your group's needs
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

CAPS_RATIO_THRESHOLD = 0.6  # If 60% or more of the message is uppercase, it's suspicious.
MIN_LENGTH_FOR_CAPS_CHECK = 10  # Don't check short messages (like "OK").

# Link: http/https, www., t.me/xxx, telegram.me/xxx
URL_PATTERN = re.compile(
    r"(https?://\S+)|(www\.\S+)|(t\.me/\S+)|(telegram\.me/\S+)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Scoring System
# Each rule has a weight; the total points determine what happens.
# You can adjust these numbers based on your group's actual experience.
# ---------------------------------------------------------------------------

RULE_WEIGHTS = {
    "banned_word": 60,  # It just goes beyond deletion.
    "link": 40,  # It only warns you, it cannot be deleted.
    "excessive_caps": 30,
}

SPAM_DELETE_THRESHOLD = 50  # Score equal to or greater than this => Delete message
SPAM_WARN_THRESHOLD = 25  # Score between this and the deletion threshold => Warning log only

# ---------------------------------------------------------------------------


def contains_banned_word(text: str) -> str | None:
    """If the text contains one of the prohibited words, it returns that word, otherwise None."""
    lowered = text.lower()
    for word in BANNED_WORDS:
        if word.lower() in lowered:
            return word
    return None


def contains_link(text: str) -> bool:
    """Does the text contain links?"""
    return bool(URL_PATTERN.search(text))


def has_excessive_caps(text: str) -> bool:
    """Is the ratio of capital letters to total letters too high?"""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < MIN_LENGTH_FOR_CAPS_CHECK:
        return False
    upper_count = sum(1 for c in letters if c.isupper())
    ratio = upper_count / len(letters)
    return ratio >= CAPS_RATIO_THRESHOLD


def analyze_message(text: str) -> dict:
    """
Analyzes and scores the message text.

Output:
    {
        "score": int, # Total suspiciousness score
        "reasons": [str, ...], # Reasons with score for each
        "is_spam": bool, # Did it pass the deletion threshold?
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
