# Cloudflare V2
# Requires Python 3.7+

import re
import time
import json
import logging
import random
from copy import deepcopy
from urllib.parse import urlparse

# ------------------------------------------------------------------------------- #

from .exceptions import (
    CloudflareCode1020,
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider,
)

# ------------------------------------------------------------------------------- #

from .captcha import Captcha

# ------------------------------------------------------------------------------- #

logger = logging.getLogger(__name__)


class CloudflareV2:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(1.0, 5.0)

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a Cloudflare v2 challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_V2_Challenge(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [403, 429, 503]
                and re.search(
                    r'''cpo.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/jsch/v1''',
                    resp.text,
                    re.M | re.S,
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a v2 hCaptcha Cloudflare challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_V2_Captcha_Challenge(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code == 403
                and re.search(
                    r'''cpo.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/(captcha|managed)/v1''',
                    resp.text,
                    re.M | re.S,
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Extract challenge data from the page
    # ------------------------------------------------------------------------------- #

    def extract_challenge_data(self, resp) -> dict:
        challenge_data_match = re.search(
            r'window\._cf_chl_opt=({.*?});',
            resp.text,
            re.DOTALL,
        )

        if not challenge_data_match:
            raise CloudflareChallengeError('Could not find Cloudflare challenge data')

        try:
            challenge_data = json.loads(challenge_data_match.group(1))
        except json.JSONDecodeError as exc:
            raise CloudflareChallengeError(
                'Cloudflare challenge data is not valid JSON'
            ) from exc

        form_action = re.search(
            r'<form .*?id="challenge-form" action="([^"]+)"',
            resp.text,
            re.DOTALL,
        )

        if not form_action:
            raise CloudflareChallengeError('Could not find Cloudflare challenge form')

        return {
            'challenge_data': challenge_data,
            'form_action': form_action.group(1),
        }

    # ------------------------------------------------------------------------------- #
    # Generate the payload for the challenge response
    # ------------------------------------------------------------------------------- #

    def generate_challenge_payload(self, challenge_data: dict, resp) -> dict:
        r_token = re.search(r'name="r" value="([^"]+)"', resp.text)
        if not r_token:
            raise CloudflareChallengeError("Could not find 'r' token")

        payload: dict = {
            'r': r_token.group(1),
            'cf_ch_verify': 'plat',
            'vc': '',
            'captcha_vc': '',
            'cf_captcha_kind': 'h',
            'h-captcha-response': '',
        }

        if 'cvId' in challenge_data:
            payload['cv_chal_id'] = challenge_data['cvId']

        if 'chlPageData' in challenge_data:
            payload['cf_chl_page_data'] = challenge_data['chlPageData']

        return payload

    # ------------------------------------------------------------------------------- #
    # Handle the Cloudflare v2 challenge
    # ------------------------------------------------------------------------------- #

    def handle_V2_Challenge(self, resp, **kwargs):
        challenge_info = self.extract_challenge_data(resp)
        time.sleep(self.delay)

        payload = self.generate_challenge_payload(challenge_info['challenge_data'], resp)

        url_parsed = urlparse(resp.url)
        challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_info['form_action']}"

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
            raise CloudflareSolveError('Failed to solve Cloudflare v2 challenge')

        return challenge_response

    # ------------------------------------------------------------------------------- #
    # Handle the Cloudflare v2 captcha challenge
    # ------------------------------------------------------------------------------- #

    def handle_V2_Captcha_Challenge(self, resp, **kwargs):
        if (
            not self.cloudscraper.captcha
            or not isinstance(self.cloudscraper.captcha, dict)
            or not self.cloudscraper.captcha.get('provider')
        ):
            self.cloudscraper.simpleException(
                CloudflareCaptchaProvider,
                'Cloudflare Captcha detected, but no captcha provider configured',
            )

        challenge_info = self.extract_challenge_data(resp)

        site_key = re.search(r'data-sitekey="([^"]+)"', resp.text)
        if not site_key:
            raise CloudflareCaptchaError('Could not find hCaptcha site key')

        payload = self.generate_challenge_payload(challenge_info['challenge_data'], resp)

        captcha_response = Captcha.dynamicImport(
            self.cloudscraper.captcha.get('provider').lower()
        ).solveCaptcha(
            'hCaptcha',
            resp.url,
            site_key.group(1),
            self.cloudscraper.captcha,
        )

        payload['h-captcha-response'] = captcha_response

        time.sleep(self.delay)

        url_parsed = urlparse(resp.url)
        challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_info['form_action']}"

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
            raise CloudflareSolveError('Failed to solve Cloudflare v2 captcha challenge')

        return challenge_response
