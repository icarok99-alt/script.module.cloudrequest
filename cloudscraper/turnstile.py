# Cloudflare Turnstile
# Requires Python 3.7+

import re
import time
import logging
import random
from copy import deepcopy
from urllib.parse import urlparse

from .exceptions import (
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider,
    CloudflareTurnstileError,
)

from .captcha import Captcha

logger = logging.getLogger(__name__)

MAX_GC_RETRIES = 3

class _TokenInterceptor:

    def __init__(self, scraper):
        self._scraper = scraper
        self._original_request = scraper.perform_request
        self.captured_token = None

    def __enter__(self):
        original = self._original_request
        interceptor = self

        def patched(method, url, **kwargs):
            params = kwargs.get('params') or {}
            if isinstance(params, dict):
                token = params.get('gc_response')
                if token and len(token) > 20:
                    interceptor.captured_token = token

            data = kwargs.get('data') or {}
            if isinstance(data, dict):
                token = data.get('gc_response')
                if token and len(token) > 20:
                    interceptor.captured_token = token

            if 'gc_response' in url:
                match = re.search(r'gc_response=([^&\s]+)', url)
                if match and len(match.group(1)) > 20:
                    interceptor.captured_token = match.group(1)

            return original(method, url, **kwargs)

        self._scraper.perform_request = patched
        return self

    def __exit__(self, *args):
        self._scraper.perform_request = self._original_request

class CloudflareTurnstile:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(1.0, 5.0)
        self.token_provider = None

    @staticmethod
    def is_Turnstile_Challenge(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [403, 429, 503]
                and (
                    re.search(r'class="cf-turnstile"', resp.text, re.M | re.S)
                    or re.search(
                        r'src="https://challenges\.cloudflare\.com/turnstile/v0/api\.js',
                        resp.text,
                        re.M | re.S,
                    )
                    or re.search(
                        r'data-sitekey="[0-9A-Za-z]{40}"',
                        resp.text,
                        re.M | re.S,
                    )
                )
            )
        except AttributeError:
            return False

    @staticmethod
    def is_GC_Challenge(resp) -> bool:
        try:
            text = resp.text.lower()
            return any(x in text for x in [
                'turnstile.render',
                'turnstile-container',
                'challenges.cloudflare.com/turnstile',
                'gc_response',
                '0x4aaaaaa',
            ])
        except Exception:
            return False

    def extract_turnstile_data(self, resp) -> dict:
        site_key = re.search(r'data-sitekey="([0-9A-Za-z]{40})"', resp.text)

        if not site_key:
            raise CloudflareTurnstileError('Could not find Turnstile site key')

        form_action = re.search(r'<form [^>]*action="([^"]+)"', resp.text, re.DOTALL)

        if form_action:
            form_action_url = form_action.group(1)
        else:
            parsed = urlparse(resp.url)
            form_action_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'

        return {
            'site_key': site_key.group(1),
            'form_action': form_action_url,
        }

    def handle_Turnstile_Challenge(self, resp, **kwargs):
        if self.token_provider:
            return self.handle_GC_Challenge(resp, **kwargs)

        if (
            not self.cloudscraper.captcha
            or not isinstance(self.cloudscraper.captcha, dict)
            or not self.cloudscraper.captcha.get('provider')
        ):
            self.cloudscraper.simpleException(
                CloudflareCaptchaProvider,
                'Cloudflare Turnstile detected, but no captcha provider configured',
            )

        turnstile_info = self.extract_turnstile_data(resp)

        time.sleep(self.delay)

        turnstile_response = Captcha.dynamicImport(
            self.cloudscraper.captcha.get('provider').lower()
        ).solveCaptcha(
            'turnstile',
            resp.url,
            turnstile_info['site_key'],
            self.cloudscraper.captcha,
        )

        payload: dict = {'cf-turnstile-response': turnstile_response}
        payload.update({
            name: value
            for name, value in re.findall(
                r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', resp.text
            )
            if name != 'cf-turnstile-response'
        })

        url_parsed = urlparse(resp.url)
        challenge_url = turnstile_info['form_action']
        if not challenge_url.startswith('http'):
            challenge_url = f'{url_parsed.scheme}://{url_parsed.netloc}{challenge_url}'

        cloudflare_kwargs = deepcopy(kwargs)
        cloudflare_kwargs['allow_redirects'] = False
        cloudflare_kwargs.setdefault('headers', {}).update({
            'Origin': f'{url_parsed.scheme}://{url_parsed.netloc}',
            'Referer': resp.url,
            'Content-Type': 'application/x-www-form-urlencoded',
        })

        challenge_response = self.cloudscraper.request(
            'POST', challenge_url, data=payload, **cloudflare_kwargs
        )

        if challenge_response.status_code == 403:
            raise CloudflareSolveError('Failed to solve Cloudflare Turnstile challenge')

        return challenge_response

    def handle_GC_Challenge(self, resp, **kwargs):
        base_headers = dict(kwargs.pop('headers', {}) or {})
        parsed = urlparse(resp.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for attempt in range(1, MAX_GC_RETRIES + 1):
            if not self.is_GC_Challenge(resp):
                return resp

            time.sleep(self.delay)

            token = None
            try:
                token = self.token_provider(resp, base_headers)
            except Exception:
                pass

            if not token:
                with _TokenInterceptor(self.cloudscraper) as interceptor:
                    try:
                        self.cloudscraper.perform_request('GET', resp.url, headers=base_headers, **kwargs)
                    except Exception:
                        pass
                    token = interceptor.captured_token

            if not token:
                token = self._gc_token_from_cookies()

            if not token:
                token = self._gc_token_from_html(resp.text)

            if not token:
                self.cloudscraper.simpleException(
                    CloudflareSolveError,
                    "Cloudflare Turnstile (gc_response) detected, but could not retrieve a valid token.",
                )

            self.cloudscraper.perform_request(
                'GET', base_url,
                params={'gc_response': token},
                headers={
                    **base_headers,
                    'Origin': base_url,
                    'Referer': resp.url,
                    'X-Requested-With': 'XMLHttpRequest',
                },
                **kwargs,
            )

            resp = self.cloudscraper.perform_request('GET', resp.url, headers=base_headers, **kwargs)

            if not self.is_GC_Challenge(resp):
                return resp

            time.sleep(self.delay * attempt)

        return resp

    def _gc_token_from_cookies(self) -> 'str | None':
        try:
            cookies = self.cloudscraper.cookies.get_dict()
            for key in ('gc_response', 'cf_turnstile_response', 'cf_clearance'):
                val = cookies.get(key)
                if val and len(val) > 20:
                    return val
        except Exception:
            pass
        return None

    def _gc_token_from_html(self, html: str) -> 'str | None':
        patterns = [
            r'name=["\']gc_response["\'][^>]*value=["\']([^"\']{20,})["\']',
            r'value=["\']([^"\']{20,})["\'][^>]*name=["\']gc_response["\']',
            r'gc_response\s*=\s*["\']([^"\']{20,})["\']',
            r'"gc_response"\s*:\s*"([^"]{20,})"',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
