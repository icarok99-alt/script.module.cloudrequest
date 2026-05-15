# cloudscraper  –  main package  (v3.1.0)
# Requires Python 3.8+

from __future__ import annotations

import re
import logging
from enum import Enum, auto
from typing import Optional

logger = logging.getLogger(__name__)

class ChallengeType(Enum):
    
    NONE = auto()

    FIREWALL_1020 = auto()
    BOT_MANAGEMENT_403 = auto()

    V1_IUAM = auto()
    V1_CAPTCHA = auto()

    V2_JS = auto()
    V2_CAPTCHA = auto()

    V3_JS = auto()

    TURNSTILE = auto()

    MANAGED = auto()

    UNKNOWN_CF = auto()

def _server_is_cloudflare(resp) -> bool:
    
    server: str = resp.headers.get("Server", "")
    return server.startswith("cloudflare") or "cf-ray" in {
        k.lower() for k in resp.headers
    }

def _status_is_challenge(status: int) -> bool:
    return status in (403, 429, 503)

def _has(text: str, *patterns: str, flags: int = re.M | re.S) -> bool:
    
    return any(re.search(p, text, flags) for p in patterns)

def is_cloudflare_response(resp) -> bool:
    
    try:
        return _server_is_cloudflare(resp)
    except AttributeError:
        return False

def detect_challenge_type(resp) -> ChallengeType:
    
    try:
        if not _server_is_cloudflare(resp):
            return ChallengeType.NONE

        text: str = resp.text or ""
        status: int = resp.status_code
        headers = resp.headers

        if status == 403 and _has(text, r'<span[^>]+class="cf-error-code"\s*>\s*1020'):
            return ChallengeType.FIREWALL_1020

        if headers.get("cf-mitigated", "").lower() == "challenge":
            pass

        if not _status_is_challenge(status):
            return ChallengeType.NONE

        if _has(
            text,
            r'class=["\']cf-turnstile["\']',
            r'src=["\']https://challenges\.cloudflare\.com/turnstile/v0/api\.js',
            r'data-sitekey=["\'][0-9A-Za-z_-]{20,}["\']',
        ):
            if _has(
                text,
                r'cf-turnstile',
                r'turnstile/v0/api\.js',
                r'challenges\.cloudflare\.com/turnstile',
            ):
                return ChallengeType.TURNSTILE

        if _has(
            text,
            r,
            r'window\._cf_chl_ctx\s*=\s*\{',
            r'<form[^>]*id=["\']challenge-form["\'][^>]*action=["\'][^"\']*__cf_chl_rt_tk=',
        ):
            return ChallengeType.V3_JS

        if _has(
            text,
            r,
        ):
            return ChallengeType.V2_CAPTCHA

        if _has(
            text,
            r,
        ):
            return ChallengeType.V2_JS

        if _has(text, r'/cdn-cgi/images/trace/(?:captcha|managed)/') and _has(
            text,
            r,
        ):
            return ChallengeType.V1_CAPTCHA

        if _has(text, r'/cdn-cgi/images/trace/jsch/') and _has(
            text,
            r,
        ):
            return ChallengeType.V1_IUAM

        if _has(
            text,
            r'class=["\']cf-challenge-running["\']',
            r'id=["\']cf-challenge-running["\']',
            r'/cdn-cgi/challenge-platform/',
        ):
            return ChallengeType.MANAGED

        if _status_is_challenge(status):
            logger.debug(
                "Cloudflare response with status %s — pattern not recognised. "
                "URL: %s",
                status,
                getattr(resp, "url", "?"),
            )
            return ChallengeType.UNKNOWN_CF

        return ChallengeType.NONE

    except AttributeError:
        return ChallengeType.NONE

def get_challenge_info(resp) -> dict:
    
    challenge_type = detect_challenge_type(resp)

    solvable = challenge_type not in (
        ChallengeType.NONE,
        ChallengeType.FIREWALL_1020,
        ChallengeType.BOT_MANAGEMENT_403,
        ChallengeType.UNKNOWN_CF,
    )

    try:
        return {
            "type": challenge_type,
            "status": resp.status_code,
            "url": resp.url,
            "server": resp.headers.get("Server", ""),
            "cf_ray": resp.headers.get("CF-RAY", ""),
            "cf_mitigated": resp.headers.get("cf-mitigated", ""),
            "solvable": solvable,
        }
    except AttributeError:
        return {
            "type": challenge_type,
            "solvable": solvable,
        }
