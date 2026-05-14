# cloudflare.py  –  Cloudflare V1 (legacy IUAM / captcha) handler
# Requires Python 3.8+

import html
import re
import time
import logging

from copy import deepcopy
from urllib.parse import urlparse, urljoin

from .exceptions import (
    CloudflareCode1020,
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider,
)
from .captcha import Captcha
from .interpreters import JavaScriptInterpreter
from .challenge_detector import ChallengeType, detect_challenge_type

logger = logging.getLogger(__name__)

class Cloudflare:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper

    @staticmethod
    def unescape(html_text: str) -> str:
        return html.unescape(html_text)

    @staticmethod
    def is_IUAM_Challenge(resp) -> bool:
        
        try:
            return detect_challenge_type(resp) == ChallengeType.V1_IUAM
        except AttributeError:
            return False

    @staticmethod
    def is_Captcha_Challenge(resp) -> bool:
        
        try:
            return detect_challenge_type(resp) == ChallengeType.V1_CAPTCHA
        except AttributeError:
            return False

    @staticmethod
    def is_Firewall_Blocked(resp) -> bool:
        
        try:
            return detect_challenge_type(resp) == ChallengeType.FIREWALL_1020
        except AttributeError:
            return False

    def is_New_IUAM_Challenge(self, resp) -> bool:
        
        try:
            ct = detect_challenge_type(resp)
            return ct in (ChallengeType.V2_JS, ChallengeType.V1_IUAM)
        except AttributeError:
            return False

    def is_New_Captcha_Challenge(self, resp) -> bool:
        
        try:
            ct = detect_challenge_type(resp)
            return ct in (ChallengeType.V2_CAPTCHA, ChallengeType.V1_CAPTCHA)
        except AttributeError:
            return False

    def is_Challenge_Request(self, resp) -> bool:
        
        ct = detect_challenge_type(resp)

        if ct == ChallengeType.FIREWALL_1020:
            self.cloudscraper.simpleException(
                CloudflareCode1020,
                "Cloudflare has blocked this request (Code 1020 Detected).",
            )

        if ct in (ChallengeType.V2_CAPTCHA, ChallengeType.MANAGED):
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                "Detected a Cloudflare version 2 Captcha / Managed challenge. "
                "This feature requires a captcha provider via the 'captcha' parameter.",
            )

        if ct == ChallengeType.V2_JS:
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                "Detected a Cloudflare version 2 JS challenge (orchestrate/jsch/v1). "
                "This feature is handled by CloudflareV2.",
            )

        if ct in (ChallengeType.V1_CAPTCHA, ChallengeType.V1_IUAM):
            if self.cloudscraper.debug:
                print(f"Detected a Cloudflare V1 challenge ({ct.name}).")
            return True

        return False

    def IUAM_Challenge_Response(self, body: str, url: str, interpreter: str) -> dict:
        form_payload = re.search(
            r'<form (?P<form>.*?=["\']challenge-form["\'] '
            r'action="(?P<challengeUUID>.*?'
            r'__cf_chl_f_tk=\S+)"(.*?)</form>)',
            body,
            re.M | re.DOTALL,
        )

        if not form_payload:
            self.cloudscraper.simpleException(
                CloudflareIUAMError,
                "Cloudflare IUAM detected, unable to extract form parameters.",
            )

        form_payload = form_payload.groupdict()
        if not all(k in form_payload for k in ["form", "challengeUUID"]):
            self.cloudscraper.simpleException(
                CloudflareIUAMError,
                "Cloudflare IUAM detected, unable to extract form parameters.",
            )

        payload: dict = {}
        for challenge_param in re.findall(
            r"^\s*<input\s(.*?)/>", form_payload["form"], re.M | re.S
        ):
            input_payload = dict(re.findall(r'(\S+)="(\S+)"', challenge_param))
            if input_payload.get("name") in ["r", "jschl_vc", "pass"]:
                payload[input_payload["name"]] = input_payload["value"]

        host_parsed = urlparse(url)

        try:
            payload["jschl_answer"] = JavaScriptInterpreter.dynamicImport(
                interpreter
            ).solveChallenge(body, host_parsed.netloc)
        except Exception as exc:
            self.cloudscraper.simpleException(
                CloudflareIUAMError,
                f"Unable to parse Cloudflare anti-bots page: {getattr(exc, 'message', exc)}",
            )

        return {
            "url": (
                f"{host_parsed.scheme}://{host_parsed.netloc}"
                f"{self.unescape(form_payload['challengeUUID'])}"
            ),
            "data": payload,
        }

    def captcha_Challenge_Response(
        self, provider: str, provider_params: dict, body: str, url: str
    ) -> dict:
        form_payload = re.search(
            r'<form (?P<form>.*?=["\']challenge-form["\'] '
            r'action="(?P<challengeUUID>.*?__cf_chl_captcha_tk__=\S+)"(.*?)</form>)',
            body,
            re.M | re.DOTALL,
        )

        if not form_payload:
            self.cloudscraper.simpleException(
                CloudflareCaptchaError,
                "Cloudflare Captcha detected, unable to extract form parameters.",
            )

        form_payload = form_payload.groupdict()
        if not all(k in form_payload for k in ["form", "challengeUUID"]):
            self.cloudscraper.simpleException(
                CloudflareCaptchaError,
                "Cloudflare Captcha detected, unable to extract form parameters.",
            )

        try:
            payload = dict(
                re.findall(
                    r'(name="r"\svalue|data-ray|data-sitekey|name="cf_captcha_kind"\svalue)="(.*?)"',
                    form_payload["form"],
                )
            )
            captcha_type = (
                "reCaptcha"
                if payload.get('name="cf_captcha_kind" value') == "re"
                else "hCaptcha"
            )
        except (AttributeError, KeyError):
            self.cloudscraper.simpleException(
                CloudflareCaptchaError,
                "Cloudflare Captcha detected, unable to extract form parameters.",
            )

        if (
            self.cloudscraper.proxies
            and self.cloudscraper.proxies != self.cloudscraper.captcha.get("proxy")
        ):
            self.cloudscraper.captcha["proxy"] = self.cloudscraper.proxies

        self.cloudscraper.captcha["User-Agent"] = self.cloudscraper.headers["User-Agent"]

        captcha_response = Captcha.dynamicImport(provider.lower()).solveCaptcha(
            captcha_type,
            url,
            payload["data-sitekey"],
            provider_params,
        )

        data_payload = {
            "r": payload.get('name="r" value', ""),
            "cf_captcha_kind": payload.get('name="cf_captcha_kind" value', ""),
            "id": payload.get("data-ray"),
            "g-recaptcha-response": captcha_response,
        }
        if captcha_type == "hCaptcha":
            data_payload["h-captcha-response"] = captcha_response

        host_parsed = urlparse(url)
        return {
            "url": (
                f"{host_parsed.scheme}://{host_parsed.netloc}"
                f"{self.unescape(form_payload['challengeUUID'])}"
            ),
            "data": data_payload,
        }

    def Challenge_Response(self, resp, **kwargs):
        if self.is_Captcha_Challenge(resp):
            if self.cloudscraper.doubleDown:
                resp = self.cloudscraper.decodeBrotli(
                    self.cloudscraper.perform_request(
                        resp.request.method, resp.url, **kwargs
                    )
                )

            if not self.is_Captcha_Challenge(resp):
                return resp

            if (
                not self.cloudscraper.captcha
                or not isinstance(self.cloudscraper.captcha, dict)
                or not self.cloudscraper.captcha.get("provider")
            ):
                self.cloudscraper.simpleException(
                    CloudflareCaptchaProvider,
                    "Cloudflare Captcha detected — no anti-captcha provider configured "
                    "via the 'captcha' parameter.",
                )

            if self.cloudscraper.captcha.get("provider") == "return_response":
                return resp

            submit_url = self.captcha_Challenge_Response(
                self.cloudscraper.captcha.get("provider"),
                self.cloudscraper.captcha,
                resp.text,
                resp.url,
            )
        else:
            if not self.cloudscraper.delay:
                try:
                    delay_match = re.search(
                        r"submit\(\);\r?\n\s*},\s*([0-9]+)", resp.text
                    )
                    delay = float(delay_match.group(1)) / 1000.0 if delay_match else 5.0
                    self.cloudscraper.delay = delay
                except (AttributeError, ValueError):
                    self.cloudscraper.simpleException(
                        CloudflareIUAMError,
                        "Cloudflare IUAM possibly malformed — could not extract delay value.",
                    )

            time.sleep(self.cloudscraper.delay)
            submit_url = self.IUAM_Challenge_Response(
                resp.text,
                resp.url,
                self.cloudscraper.interpreter,
            )

        if submit_url:
            def _merge(obj: dict, key: str, extra: dict) -> dict:
                obj.setdefault(key, {}).update(extra)
                return obj[key]

            cloudflare_kwargs = deepcopy(kwargs)
            cloudflare_kwargs["allow_redirects"] = False
            cloudflare_kwargs["data"] = _merge(
                cloudflare_kwargs, "data", submit_url["data"]
            )

            url_parsed = urlparse(resp.url)
            cloudflare_kwargs["headers"] = _merge(
                cloudflare_kwargs,
                "headers",
                {
                    "Origin": f"{url_parsed.scheme}://{url_parsed.netloc}",
                    "Referer": resp.url,
                },
            )

            challenge_submit_response = self.cloudscraper.request(
                "POST", submit_url["url"], **cloudflare_kwargs
            )

            if challenge_submit_response.status_code == 400:
                self.cloudscraper.simpleException(
                    CloudflareSolveError,
                    "Invalid V1 challenge answer — Cloudflare may have changed its format.",
                )

            if not challenge_submit_response.is_redirect:
                return challenge_submit_response

            cloudflare_kwargs = deepcopy(kwargs)
            cloudflare_kwargs["headers"] = _merge(
                cloudflare_kwargs,
                "headers",
                {"Referer": challenge_submit_response.url},
            )

            location = challenge_submit_response.headers["Location"]
            redirect_location = (
                urljoin(challenge_submit_response.url, location)
                if not urlparse(location).netloc
                else location
            )

            return self.cloudscraper.request(
                resp.request.method, redirect_location, **cloudflare_kwargs
            )

        return self.cloudscraper.request(resp.request.method, resp.url, **kwargs)
