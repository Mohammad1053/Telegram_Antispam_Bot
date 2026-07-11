"""
Flood Join Detector.

When several new members join a group in a short period of time,

it is usually a sign of a spam/advertising bot attack. This module does two things:

1. It records the join time of each new member (group by group) and warns if the number of joins in a period exceeds the allowed limit.

2. It keeps the join time of each user separate so that if they send a suspicious message immediately after
joining, they get extra points."""

from collections import defaultdict, deque
from time import time

# ---------------------------------------------------------------------------
# Editable settings
# ---------------------------------------------------------------------------

FLOOD_JOIN_COUNT = 4  # This number is...
FLOOD_JOIN_WINDOW_SECONDS = 60  # ...within this interval (seconds) => Suspicious

NEW_USER_GRACE_SECONDS = 300  # The first 5 minutes after joining, the user is considered a "newcomer".
NEW_USER_BONUS_SCORE = 20  # This point is added if the newcomer sends a previously suspicious message.

# ---------------------------------------------------------------------------

# Group's last joins: {chat_id: deque[timestamp, ...]}
_chat_joins: dict[int, deque] = defaultdict(lambda: deque(maxlen=FLOOD_JOIN_COUNT * 3))

# User's join time: {user_id: timestamp}
_user_join_time: dict[int, float] = {}


def record_join(chat_id: int, user_id: int) -> dict:
    """
Called when a new member joins the group.

Output:
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
    """If the user is still in the "newcomer" range, it returns the bonus points, otherwise zero."""
    join_time = _user_join_time.get(user_id)
    if join_time is None:
        return 0  # We did not see the time of his joining (for example, he joined before the robot started)

    if time() - join_time <= NEW_USER_GRACE_SECONDS:
        return NEW_USER_BONUS_SCORE

    return 0
