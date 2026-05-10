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

    # ------------------------------------------------------------------------------- #
    # Extract Turnstile challenge data from the page
    # ------------------------------------------------------------------------------- #

    def extract_turnstile_data(self, resp) -> dict:
        site_key = re.search(r'data-sitekey="([0-9A-Za-z]{40})"', resp.text)

        if not site_key:
            raise CloudflareTurnstileError('Could not find Turnstile site key')

        form_action = re.search(r'<form [^>]*action="([^"]+)"', resp.text, re.DOTALL)

        if form_action:
            form_action_url = form_action.group(1)
        else:
            # Fall back to the current page URL (without query string / fragment)
            parsed = urlparse(resp.url)
            form_action_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'

        return {
            'site_key': site_key.group(1),
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

        # Collect any additional hidden form fields from the page
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
