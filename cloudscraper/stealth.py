# cloudscraper  –  main package  (v3.1.0)
# Requires Python 3.8+

from __future__ import annotations

import logging
import random
import time
from typing import Any

logger = logging.getLogger(__name__)

_BROWSER_QUIRKS: dict[str, dict] = {
    "chrome": {
        "order": [
            "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile",
            "sec-ch-ua-platform", "User-Agent", "Accept", "Sec-Fetch-Site",
            "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language", "Cookie",
        ],
        "headers": {
            "sec-ch-ua": '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    "firefox": {
        "order": [
            "Host", "User-Agent", "Accept", "Accept-Language",
            "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests",
            "Referer", "Cookie",
        ],
        "headers": {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
        },
    },
}

_ACCEPT_VARIANTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

_LANGUAGE_VARIANTS = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-CA,en;q=0.9,en-US;q=0.8",
    "en-AU,en;q=0.9,en-US;q=0.8",
]

class StealthMode:

    def __init__(
        self,
        cloudscraper,
        *,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
        human_like_delays: bool = True,
        randomize_headers: bool = True,
        browser_quirks: bool = True,
    ) -> None:
        self.cloudscraper = cloudscraper
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.human_like_delays = human_like_delays
        self.randomize_headers = randomize_headers
        self.browser_quirks = browser_quirks

        self._request_count: int = 0
        self._last_request_time: float = 0.0

    def apply_stealth_techniques(self, method: str, url: str, **kwargs: Any) -> dict:
        if self.human_like_delays:
            self._apply_human_like_delay()

        if self.randomize_headers:
            kwargs = self._randomize_headers(kwargs)

        if self.browser_quirks:
            kwargs = self._apply_browser_quirks(kwargs)

        self._request_count += 1
        self._last_request_time = time.monotonic()

        return kwargs

    def _apply_human_like_delay(self) -> None:
        if self._request_count == 0:
            return

        delay = random.uniform(self.min_delay, self.max_delay)

        if random.random() < 0.1:
            delay = min(delay * 1.5, 10.0)

        if delay >= 0.1:
            logger.debug("Applying human-like delay of %.2f seconds.", delay)
            time.sleep(delay)

    def _randomize_headers(self, kwargs: dict) -> dict:
        headers: dict = dict(kwargs.get("headers", {}))

        headers.setdefault("Accept", random.choice(_ACCEPT_VARIANTS))
        headers.setdefault("Accept-Language", random.choice(_LANGUAGE_VARIANTS))

        if random.random() < 0.5:
            headers.setdefault("DNT", "1")

        kwargs["headers"] = headers
        return kwargs

    def _apply_browser_quirks(self, kwargs: dict) -> dict:
        user_agent: str = kwargs.get("headers", {}).get("User-Agent", "")
        browser_type = "firefox" if "Firefox/" in user_agent else "chrome"

        quirk = _BROWSER_QUIRKS[browser_type]
        headers: dict = dict(kwargs.get("headers", {}))

        for header, value in quirk["headers"].items():
            headers.setdefault(header, value)

        ordered: dict = {}
        for header in quirk["order"]:
            if header in headers:
                ordered[header] = headers.pop(header)
        ordered.update(headers)

        kwargs["headers"] = ordered
        return kwargs

    def set_delay_range(self, min_delay: float, max_delay: float) -> None:
        self.min_delay = min_delay
        self.max_delay = max_delay

    def enable_human_like_delays(self, enabled: bool = True) -> None:
        self.human_like_delays = enabled

    def enable_randomize_headers(self, enabled: bool = True) -> None:
        self.randomize_headers = enabled

    def enable_browser_quirks(self, enabled: bool = True) -> None:
        self.browser_quirks = enabled
