# turnstile.py  –  Cloudflare Turnstile widget challenge handler
# Requires Python 3.8+

import re
import time
import logging
import random
from copy import deepcopy
from urllib.parse import urlparse, urljoin

from .exceptions import (
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaProvider,
    CloudflareTurnstileError,
)
from .captcha import Captcha
from .challenge_detector import ChallengeType, detect_challenge_type

logger = logging.getLogger(__name__)

_SITEKEY_RE = re.compile(
    r'data-sitekey=["\']([0-9A-Za-z_\-]{20,})["\']'
)

class CloudflareTurnstile:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(1.0, 4.0)

    @staticmethod
    def is_Turnstile_Challenge(resp) -> bool:
        try:
            return detect_challenge_type(resp) == ChallengeType.TURNSTILE
        except AttributeError:
            return False

    def extract_turnstile_data(self, resp) -> dict:
        
        text = resp.text

        site_key_match = re.search(
            r'<(?:div|span)[^>]+class=["\'][^"\']*cf-turnstile[^"\']*["\'][^>]*'
            r'data-sitekey=["\']([0-9A-Za-z_\-]{20,})["\']',
            text,
            re.DOTALL,
        ) or re.search(
            r'<(?:div|span)[^>]+data-sitekey=["\']([0-9A-Za-z_\-]{20,})["\'][^>]*'
            r'class=["\'][^"\']*cf-turnstile',
            text,
            re.DOTALL,
        ) or _SITEKEY_RE.search(text)

        if not site_key_match:
            raise CloudflareTurnstileError(
                "Could not find a Turnstile site key in the challenge page."
            )

        site_key = site_key_match.group(1)

        form_action_match = re.search(
            r'<form[^>]*id=["\']challenge-form["\'][^>]*action="([^"]+)"',
            text,
            re.DOTALL,
        ) or re.search(
            r'<form[^>]*action="([^"]+)"[^>]*id=["\']challenge-form["\']',
            text,
            re.DOTALL,
        )

        if form_action_match:
            form_action = form_action_match.group(1)
            if not form_action.startswith("http"):
                parsed = urlparse(resp.url)
                form_action = f"{parsed.scheme}://{parsed.netloc}{form_action}"
        else:
            parsed = urlparse(resp.url)
            form_action = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            logger.debug(
                "Turnstile: no challenge-form found; defaulting form_action to %s",
                form_action,
            )

        form_body_match = re.search(
            r'<form[^>]*id=["\']challenge-form["\'][^>]*>(.*?)</form>',
            text,
            re.DOTALL,
        )
        scope = form_body_match.group(1) if form_body_match else text

        hidden: dict = {}
        for attrs in re.findall(r"<input([^>]+)>", scope, re.IGNORECASE):
            name_m = re.search(r'name=["\']([^"\']+)["\']', attrs)
            val_m = re.search(r'value=["\']([^"\']*)["\']', attrs)
            if name_m and name_m.group(1) != "cf-turnstile-response":
                hidden[name_m.group(1)] = val_m.group(1) if val_m else ""

        return {
            "site_key": site_key,
            "form_action": form_action,
            "hidden": hidden,
        }

    def handle_Turnstile_Challenge(self, resp, **kwargs):
        
        if (
            not self.cloudscraper.captcha
            or not isinstance(self.cloudscraper.captcha, dict)
            or not self.cloudscraper.captcha.get("provider")
        ):
            self.cloudscraper.simpleException(
                CloudflareCaptchaProvider,
                "Cloudflare Turnstile detected but no captcha provider was configured. "
                "Pass captcha={'provider': '<name>', ...} to create_scraper().",
            )

        try:
            turnstile_info = self.extract_turnstile_data(resp)
        except CloudflareTurnstileError:
            raise
        except Exception as exc:
            raise CloudflareTurnstileError(
                f"Error extracting Turnstile data: {exc}"
            ) from exc

        if self.cloudscraper.debug:
            print(
                f"Turnstile site key: {turnstile_info['site_key']} | "
                f"form action: {turnstile_info['form_action']}"
            )

        time.sleep(self.delay)

        try:
            token = Captcha.dynamicImport(
                self.cloudscraper.captcha.get("provider").lower()
            ).solveCaptcha(
                "turnstile",
                resp.url,
                turnstile_info["site_key"],
                self.cloudscraper.captcha,
            )
        except Exception as exc:
            raise CloudflareTurnstileError(
                f"Captcha provider failed to solve Turnstile: {exc}"
            ) from exc

        payload: dict = {"cf-turnstile-response": token}
        payload.update(turnstile_info["hidden"])

        url_parsed = urlparse(resp.url)
        challenge_url = turnstile_info["form_action"]

        cloudflare_kwargs = deepcopy(kwargs)
        cloudflare_kwargs["allow_redirects"] = False
        cloudflare_kwargs.setdefault("headers", {}).update(
            {
                "Origin": f"{url_parsed.scheme}://{url_parsed.netloc}",
                "Referer": resp.url,
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )

        challenge_response = self.cloudscraper.request(
            "POST", challenge_url, data=payload, **cloudflare_kwargs
        )

        if challenge_response.status_code == 403:
            raise CloudflareSolveError(
                "Turnstile token was rejected by Cloudflare (HTTP 403). "
                "The provider may have returned an invalid token."
            )

        return challenge_response
