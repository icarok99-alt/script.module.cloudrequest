# cloudscraper  –  main package  (v3.1.0)
# Requires Python 3.8+

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Union

logger = logging.getLogger(__name__)

RotationStrategy = Literal["sequential", "random", "smart"]

@dataclass
class _ProxyStat:
    success: int = 0
    failure: int = 0
    last_used: float = 0.0

    @property
    def success_rate(self) -> float:
        total = self.success + self.failure
        return self.success / total if total else 0.0

class ProxyManager:

    def __init__(
        self,
        proxies: Optional[Union[List[str], Dict[str, str], str]] = None,
        proxy_rotation_strategy: RotationStrategy = "sequential",
        ban_time: float = 300.0,
    ) -> None:
        self.rotation_strategy: RotationStrategy = proxy_rotation_strategy
        self.ban_time: float = ban_time

        self._proxies: list[str] = []
        self._current_index: int = 0
        self._banned: dict[str, float] = {}
        self._stats: dict[str, _ProxyStat] = {}

        self._load_proxies(proxies)

        logger.debug(
            "ProxyManager initialised with %d proxies using '%s' strategy.",
            len(self._proxies),
            proxy_rotation_strategy,
        )

    def _load_proxies(
        self, proxies: Optional[Union[List[str], Dict[str, str], str]]
    ) -> None:
        if not proxies:
            return
        if isinstance(proxies, str):
            self._proxies = [proxies]
        elif isinstance(proxies, list):
            self._proxies = list(proxies)
        elif isinstance(proxies, dict):
            seen: set[str] = set()
            for proxy in proxies.values():
                if proxy and proxy not in seen:
                    self._proxies.append(proxy)
                    seen.add(proxy)

    def _is_available(self, proxy: str) -> bool:
        ban_ts = self._banned.get(proxy)
        return ban_ts is None or (time.monotonic() - ban_ts) > self.ban_time

    def _available_proxies(self) -> list[str]:
        return [p for p in self._proxies if self._is_available(p)]

    def _stat(self, proxy: str) -> _ProxyStat:
        if proxy not in self._stats:
            self._stats[proxy] = _ProxyStat()
        return self._stats[proxy]

    def get_proxy(self) -> Optional[Dict[str, str]]:
        if not self._proxies:
            return None

        available = self._available_proxies()

        if not available:
            logger.warning("All proxies are banned. Unbanning the least recently banned one.")
            proxy = min(self._banned, key=self._banned.__getitem__)
            del self._banned[proxy]
            available = [proxy]

        if self.rotation_strategy == "random":
            proxy = random.choice(available)
        elif self.rotation_strategy == "smart":
            proxy = max(available, key=lambda p: self._stat(p).success_rate)
        else:
            self._current_index %= len(available)
            proxy = available[self._current_index]
            self._current_index += 1

        self._stat(proxy).last_used = time.monotonic()
        return self._format_proxy(proxy)

    @staticmethod
    def _format_proxy(proxy: str) -> Dict[str, str]:
        if proxy.startswith(("http://", "https://")):
            return {"http": proxy, "https": proxy}
        normalised = f'http://{proxy}'
        return {"http": normalised, "https": normalised}

    @staticmethod
    def _extract_url(proxy: Union[Dict[str, str], str]) -> Optional[str]:
        if isinstance(proxy, dict):
            return proxy.get("https") or proxy.get("http")
        return proxy

    def report_success(self, proxy: Union[Dict[str, str], str]) -> None:
        url = self._extract_url(proxy)
        if url:
            self._stat(url).success += 1
            self._banned.pop(url, None)

    def report_failure(self, proxy: Union[Dict[str, str], str]) -> None:
        url = self._extract_url(proxy)
        if url:
            self._stat(url).failure += 1
            self._banned[url] = time.monotonic()

    def add_proxy(self, proxy: str) -> None:
        if proxy not in self._proxies:
            self._proxies.append(proxy)
            logger.debug("Added proxy: %s", proxy)

    def remove_proxy(self, proxy: str) -> None:
        if proxy in self._proxies:
            self._proxies.remove(proxy)
            self._banned.pop(proxy, None)
            self._stats.pop(proxy, None)
            logger.debug("Removed proxy: %s", proxy)

    def get_stats(self) -> dict:
        return {
            "total_proxies": len(self._proxies),
            "available_proxies": len(self._available_proxies()),
            "banned_proxies": len(self._banned),
            "proxy_stats": {
                url: {
                    "success": s.success,
                    "failure": s.failure,
                    "success_rate": round(s.success_rate, 4),
                    "last_used": s.last_used,
                }
                for url, s in self._stats.items()
            },
        }
