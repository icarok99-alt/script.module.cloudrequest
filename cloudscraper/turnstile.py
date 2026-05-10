# Cloudflare Turnstile
# Requires Python 3.7+

import re
import time
import logging
import random
from copy import deepcopy
from urllib.parse import urlparse

# ------------------------------------------------------------------------------- #

from .exceptions import (
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider,
    CloudflareTurnstileError,
)

# ------------------------------------------------------------------------------- #

from .captcha import Captcha

# ------------------------------------------------------------------------------- #

logger = logging.getLogger(__name__)


class CloudflareTurnstile:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(1.0, 5.0)

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a Cloudflare Turnstile challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_Turnstile_Challenge(resp) -> bool:
        try:
            if not resp.headers.get('Server', '').lower().startswith('cloudflare'):
                return False

            if resp.status_code not in [403, 429, 503]:
                return False

            text = resp.text.lower()

            patterns = [
                r'challenges\.cloudflare\.com/turnstile/v0/api\.js',
                r'turnstile\.render',
                r'sitekey["\']?\s*:\s*["\']0x[0-9a-z]+',
                r'data-sitekey=["\'][0-9a-z]{40}',
                r'id=["\'](?:turnstile-container|cf-turnstile)',
                r'class=["\'][^"\']*g-recaptcha',
                r'cf-turnstile',
            ]

            return any(re.search(pattern, text, re.I | re.M | re.S) for pattern in patterns)

        except Exception:
            return False

    # ------------------------------------------------------------------------------- #
    # Extract Turnstile challenge data from the page
    # ------------------------------------------------------------------------------- #

    def extract_turnstile_data(self, resp) -> dict:
        text = resp.text

        site_key_match = re.search(
            r'sitekey\s*:\s*["\']([0-9A-Za-z_-]{40,})["\']', text, re.I
        )
        
        if not site_key_match:
            site_key_match = re.search(
                r'data-sitekey=["\']([0-9A-Za-z]{40})["\']', text, re.I
            )

        if not site_key_match:
            raise CloudflareTurnstileError('Could not find Turnstile site key')

        site_key = site_key_match.group(1)

        form_action = re.search(
            r'<form[^>]*action=["\']([^"\']+)', text, re.DOTALL | re.I
        )

        if form_action:
            form_action_url = form_action.group(1)
        else:
            parsed = urlparse(resp.url)
            form_action_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'

        return {
            'site_key': site_key,
            'form_action': form_action_url,
        }

    # ------------------------------------------------------------------------------- #
    # Handle the Cloudflare Turnstile challenge
    # ------------------------------------------------------------------------------- #

    def handle_Turnstile_Challenge(self, resp, **kwargs):
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
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                resp.text,
                re.I
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
