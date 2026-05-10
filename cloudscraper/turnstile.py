# Cloudflare Turnstile
# Requires Python 3.7+

import re
import time
import logging
import random
from urllib.parse import urlparse

# ------------------------------------------------------------------------------- #

from .exceptions import (
    CloudflareSolveError,
    CloudflareTurnstileError,
)

# ------------------------------------------------------------------------------- #

logger = logging.getLogger(__name__)

MAX_TURNSTILE_RETRIES = 3

# ------------------------------------------------------------------------------- #


class _TokenInterceptor:

    def __init__(self, scraper):
        self._scraper = scraper
        self._original_request = scraper.request
        self.captured_token = None

    def __enter__(self):
        original = self._original_request
        interceptor = self

        def patched_request(method, url, **kwargs):
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

        self._scraper.request = patched_request
        return self

    def __exit__(self, *args):
        self._scraper.request = self._original_request


# ------------------------------------------------------------------------------- #


class CloudflareTurnstile:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = getattr(cloudscraper, 'delay', random.uniform(2.0, 5.0))

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a Cloudflare Turnstile challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_Turnstile_Challenge(resp) -> bool:
        try:
            text = resp.text.lower()
            if 'dsplayer' in text:
                return False
            return any(x in text for x in [
                'turnstile.render',
                'turnstile-container',
                'challenges.cloudflare.com/turnstile',
                'gc_response',
                '0x4aaaaaa',
            ])
        except Exception:
            return False

    # ------------------------------------------------------------------------------- #
    # Extract sitekey and validation endpoint from challenge page
    # ------------------------------------------------------------------------------- #

    def extract_turnstile_data(self, resp) -> dict:
        text = resp.text

        patterns = [
            r'sitekey["\']?\s*:\s*["\']([0-9A-Za-z_-]{10,60})["\']',
            r'sitekey\s*=\s*["\']([0-9A-Za-z_-]{10,60})["\']',
            r'turnstile\.render\s*\([^)]*["\']([0-9A-Za-z_-]{10,60})["\']',
            r'["\']0x([0-9A-Za-z_-]{10,58})["\']',
        ]

        site_key = None
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                candidate = match.group(1)
                if not candidate.startswith('0x'):
                    candidate = '0x' + candidate
                site_key = candidate
                break

        if not site_key:
            self.cloudscraper.simpleException(
                CloudflareTurnstileError,
                "Cloudflare Turnstile detected, unfortunately we can't extract the sitekey correctly.",
            )

        validate_match = re.search(r'["\'](/(?:dood|pass)\?op=validate[^"\']*)["\']', text)
        form_action = validate_match.group(1) if validate_match else '/dood?op=validate'

        return {
            'site_key': site_key,
            'form_action': form_action,
            'page_url': resp.url,
        }

    # ------------------------------------------------------------------------------- #
    # Attempt to handle and send the Turnstile challenge response
    # ------------------------------------------------------------------------------- #

    def handle_Turnstile_Challenge(self, resp, **kwargs):
        base_headers = dict(kwargs.pop('headers', {}) or {})
        parsed = urlparse(resp.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for attempt in range(1, MAX_TURNSTILE_RETRIES + 1):
            if not self.is_Turnstile_Challenge(resp):
                return resp

            turnstile_info = self.extract_turnstile_data(resp)

            time.sleep(self.delay)

            # ------------------------------------------------------------------------------- #
            # Intercept gc_response from internal cloudscraper requests
            # ------------------------------------------------------------------------------- #

            token = None
            with _TokenInterceptor(self.cloudscraper) as interceptor:
                try:
                    self.cloudscraper.get(resp.url, headers=base_headers, **kwargs)
                except Exception:
                    pass
                token = interceptor.captured_token

            # ------------------------------------------------------------------------------- #
            # Fallback: extract from cookies saved by the scraper
            # ------------------------------------------------------------------------------- #

            if not token:
                token = self._extract_from_cookies()

            # ------------------------------------------------------------------------------- #
            # Fallback: extract from hidden field or JS variable in page HTML
            # ------------------------------------------------------------------------------- #

            if not token:
                token = self._extract_token_from_html(resp.text)

            if not token:
                self.cloudscraper.simpleException(
                    CloudflareSolveError,
                    "Cloudflare Turnstile detected, unfortunately we can't retrieve a valid gc_response token.",
                )

            # ------------------------------------------------------------------------------- #
            # Send the Turnstile challenge response back to the server
            # ------------------------------------------------------------------------------- #

            validate_url = base_url + turnstile_info['form_action']

            cloudflare_kwargs = dict(kwargs)
            cloudflare_kwargs['params'] = {'gc_response': token}
            cloudflare_kwargs['headers'] = {
                **base_headers,
                'Origin': base_url,
                'Referer': resp.url,
                'X-Requested-With': 'XMLHttpRequest',
            }

            self.cloudscraper.request('GET', validate_url, **cloudflare_kwargs)

            resp = self.cloudscraper.request('GET', resp.url, headers=base_headers, **kwargs)

            if not self.is_Turnstile_Challenge(resp):
                return resp

            time.sleep(self.delay * attempt)

        # Shouldn't reach here — return last response and let caller handle it.
        return resp

    # ------------------------------------------------------------------------------- #

    def _extract_from_cookies(self) -> str | None:
        try:
            cookies = self.cloudscraper.cookies.get_dict()
            for key in ('gc_response', 'cf_turnstile_response', 'cf_clearance'):
                val = cookies.get(key)
                if val and len(val) > 20:
                    return val
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------------------- #

    def _extract_token_from_html(self, html: str) -> str | None:
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
