"""
Flood / Repeated Message Detector module.

Unlike spam_detector.py which only looks at the text of *one*
message, this module keeps a history of each user's last few
messages (only in memory, not in the database - as this is only
needed for short-term comparison) and detects if a user sends the
same or very similar messages in a row (common advertising copy-paste).
"""

from collections import defaultdict, deque
from difflib import SequenceMatcher
from time import time

# ---------------------------------------------------------------------------
# Editable settings
# ---------------------------------------------------------------------------

HISTORY_SIZE = 5  # How many last messages should we keep for each user?
TIME_WINDOW_SECONDS = 60  # Messages older than these few seconds will no longer count.
SIMILARITY_THRESHOLD = 0.9  # Similarity higher than this means "same message" (0 to 1)
REPEAT_COUNT_THRESHOLD = 3  # This number of repetitions is similar => considered spam.
RULE_WEIGHT = 70  # The point that this rule adds to the total points

# ---------------------------------------------------------------------------

# User history: {user_id: deque[(timestamp, normalized_text), ...]}
_user_history: dict[int, deque] = defaultdict(lambda: deque(maxlen=HISTORY_SIZE))


def _normalize(text: str) -> str:
    """Ignores extra spaces and upper/lower case letters to make the comparison more accurate."""
    return " ".join(text.strip().lower().split())


def _is_similar(a: str, b: str) -> bool:
    if a == b:
        return True
    return SequenceMatcher(None, a, b).ratio() >= SIMILARITY_THRESHOLD


def check_repetition(user_id: int, text: str) -> dict:
    """
    Compares a user's new message with their recent message history.

Output:
    {
        "is_repeated": bool, # Is the repetition limit exceeded?
        "repeat_count": int, # How many times is this message the same (including itself)?
        "score": int, # The score to add to the total
    }
    """
    now = time()
    normalized = _normalize(text)
    history = _user_history[user_id]

    # Discard messages outside of the time frame.
    while history and now - history[0][0] > TIME_WINDOW_SECONDS:
        history.popleft()

    similar_count = sum(
        1 for _, old_text in history if _is_similar(normalized, old_text)
    )

    history.append((now, normalized))

    repeat_count = similar_count + 1  # +1 means the same message
    is_repeated = repeat_count >= REPEAT_COUNT_THRESHOLD

    return {
        "is_repeated": is_repeated,
        "repeat_count": repeat_count,
        "score": RULE_WEIGHT if is_repeated else 0,
    }
