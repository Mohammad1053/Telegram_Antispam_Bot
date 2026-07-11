"""
Link checking module with external Google Safe Browsing API service.

Extracts links inside a message and asks Google service whether
they are on Google's list of malicious/phishing sites or not.

Requires a free API Key from Google Cloud Console (free, explained in the project's README).
If the API Key is not set, this module will just
fail-open - the rest of the bot will work without this feature.

Note about API version: We use Lookup API version v4. Although
Google has declared this version "deprecated" and is migrating
to version v5, v4 is still fully functional, stable and well documented.

The alternative version (v5alpha1) is still
experimental and has shown unreliable behavior in practice - so for now, v4 is a safer choice.

Another point: if the Google service itself is unavailable or gives an error,
instead of stopping the bot, we just ignore it (fail-open) - because this is an additional layer,
not the main part of spam detection.
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

RULE_WEIGHT = 100  # If Google confirms that the link is malicious, it will automatically pass the removal threshold.

CLIENT_ID = "antispam-telegram-bot"
CLIENT_VERSION = "1.0"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def extract_urls(text: str) -> list[str]:
    """Extracts links within a text."""
    matches = URL_EXTRACT_PATTERN.findall(text)
    return [http_match or www_match for http_match, www_match in matches if http_match or www_match]


async def check_urls(urls: list[str], api_key: str | None) -> dict:
    """
   Gives a list of links in a request to Google and checks whether they are malicious or not.

Output:
    {
        "is_malicious": bool,
        "matched_urls": [str, ...], # links that were found to be malicious
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
