# cloudscraper  –  main package  (v3.1.0)
# Requires Python 3.8+

import re
import time
import json
import logging
import random
from copy import deepcopy
from urllib.parse import urlparse

from .exceptions import (
    CloudflareCode1020,
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider,
)
from .captcha import Captcha
from .challenge_detector import ChallengeType, detect_challenge_type

logger = logging.getLogger(__name__)

class CloudflareV2:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(2.0, 6.0)

    @staticmethod
    def is_V2_Challenge(resp) -> bool:
        
        try:
            return detect_challenge_type(resp) == ChallengeType.V2_JS
        except AttributeError:
            return False

    @staticmethod
    def is_V2_Captcha_Challenge(resp) -> bool:
        
        try:
            return detect_challenge_type(resp) == ChallengeType.V2_CAPTCHA
        except AttributeError:
            return False

    def extract_challenge_data(self, resp) -> dict:
        
        opt_match = re.search(
            r"window\._cf_chl_opt\s*=\s*({.*?});",
            resp.text,
            re.DOTALL,
        )
        if not opt_match:
            raise CloudflareChallengeError(
                "Could not locate window._cf_chl_opt in the challenge page."
            )

        try:
            challenge_data = json.loads(opt_match.group(1))
        except json.JSONDecodeError as exc:
            raise CloudflareChallengeError(
                f"window._cf_chl_opt is not valid JSON: {exc}"
            ) from exc

        chl_data_match = re.search(
            r"window\._cf_chl_data\s*=\s*({.*?});",
            resp.text,
            re.DOTALL,
        )
        if chl_data_match:
            try:
                challenge_data["_chl_data"] = json.loads(chl_data_match.group(1))
            except json.JSONDecodeError:
                pass

        form_action_match = re.search(
            r'<form[^>]*id=["\']challenge-form["\'][^>]*action="([^"]+)"',
            resp.text,
            re.DOTALL,
        ) or re.search(
            r'<form[^>]*action="([^"]+)"[^>]*id=["\']challenge-form["\']',
            resp.text,
            re.DOTALL,
        )

        if not form_action_match:
            raise CloudflareChallengeError(
                "Could not find the challenge form action in the V2 page."
            )

        return {
            "challenge_data": challenge_data,
            "form_action": form_action_match.group(1),
        }

    def _collect_hidden_fields(self, resp_text: str) -> dict:
        
        form_body_match = re.search(
            r'<form[^>]*id=["\']challenge-form["\'][^>]*>(.*?)</form>',
            resp_text,
            re.DOTALL,
        )
        scope = form_body_match.group(1) if form_body_match else resp_text

        fields: dict = {}
        for attrs in re.findall(r"<input([^>]+)>", scope, re.IGNORECASE):
            name_m = re.search(r'name=["\']([^"\']+)["\']', attrs)
            val_m = re.search(r'value=["\']([^"\']*)["\']', attrs)
            if name_m:
                fields[name_m.group(1)] = val_m.group(1) if val_m else ""
        return fields

    def generate_challenge_payload(self, challenge_data: dict, resp) -> dict:
        
        hidden = self._collect_hidden_fields(resp.text)

        r_value = hidden.get("r", "")
        if not r_value:
            r_match = re.search(r'name="r"\s+value="([^"]+)"', resp.text)
            if not r_match:
                raise CloudflareChallengeError("Could not find the 'r' token in the V2 form.")
            r_value = r_match.group(1)

        payload: dict = {
            "r": r_value,
            "cf_ch_verify": "plat",
            "vc": hidden.get("vc", ""),
            "captcha_vc": hidden.get("captcha_vc", ""),
            "cf_captcha_kind": hidden.get("cf_captcha_kind", "h"),
            "h-captcha-response": "",
        }

        chl = challenge_data.get("challenge_data", challenge_data)
        for src_key, dst_key in (
            ("cvId",        "cv_chal_id"),
            ("chlPageData", "cf_chl_page_data"),
            ("cZone",       "cf_zone_id"),
        ):
            if src_key in chl:
                payload[dst_key] = chl[src_key]

        for k, v in hidden.items():
            payload.setdefault(k, v)

        return payload

    def handle_V2_Challenge(self, resp, **kwargs):
        
        challenge_info = self.extract_challenge_data(resp)
        time.sleep(self.delay)

        payload = self.generate_challenge_payload(challenge_info, resp)

        url_parsed = urlparse(resp.url)
        challenge_url = challenge_info["form_action"]
        if not challenge_url.startswith("http"):
            challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_url}"

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
                "Failed to solve Cloudflare V2 JS challenge — server returned 403."
            )

        return challenge_response

    def handle_V2_Captcha_Challenge(self, resp, **kwargs):
        
        if (
            not self.cloudscraper.captcha
            or not isinstance(self.cloudscraper.captcha, dict)
            or not self.cloudscraper.captcha.get("provider")
        ):
            self.cloudscraper.simpleException(
                CloudflareCaptchaProvider,
                "Cloudflare V2 Captcha / Managed challenge detected but no "
                "captcha provider was configured.",
            )

        challenge_info = self.extract_challenge_data(resp)

        site_key_match = re.search(
            r'data-sitekey=["\']([0-9A-Za-z_-]{20,})["\']', resp.text
        )
        if not site_key_match:
            raise CloudflareCaptchaError(
                "Could not find an hCaptcha / reCaptcha site key in the V2 page."
            )

        payload = self.generate_challenge_payload(challenge_info, resp)

        captcha_response = Captcha.dynamicImport(
            self.cloudscraper.captcha.get("provider").lower()
        ).solveCaptcha(
            "hCaptcha",
            resp.url,
            site_key_match.group(1),
            self.cloudscraper.captcha,
        )

        payload["h-captcha-response"] = captcha_response

        time.sleep(self.delay)

        url_parsed = urlparse(resp.url)
        challenge_url = challenge_info["form_action"]
        if not challenge_url.startswith("http"):
            challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_url}"

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
                "Failed to solve Cloudflare V2 Captcha challenge — server returned 403."
            )

        return challenge_response
