# Cloudflare Turnstile
# Python 3

import re
import time
import json
import logging
import random
from copy import deepcopy
from collections import OrderedDict
from urllib.parse import urlparse, urljoin

from .exceptions import (
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
    CloudflareCaptchaProvider,
    CloudflareTurnstileError
)

from .captcha import Captcha


class CloudflareTurnstile():

    def __init__(self, cloudscraper):
        self.cloudscraper = cloudscraper
        self.delay = self.cloudscraper.delay or random.uniform(1.0, 5.0)

    @staticmethod
    def is_Turnstile_Challenge(resp):
        try:
            return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [403, 429, 503]
                and (
                    re.search(r'class="cf-turnstile"', resp.text, re.M | re.S)
                    or re.search(
                        r'src="https://challenges.cloudflare.com/turnstile/v0/api.js',
                        resp.text,
                        re.M | re.S
                    )
                    or re.search(r'data-sitekey="[0-9A-Za-z]{40}"', resp.text, re.M | re.S)
                )
            )
        except AttributeError:
            pass

        return False

    def extract_turnstile_data(self, resp):
        try:
            site_key = re.search(r'data-sitekey="([0-9A-Za-z]{40})"', resp.text)

            if not site_key:
                raise CloudflareTurnstileError("Could not find Turnstile site key")

            form_action = re.search(r'<form .*?action="([^"]+)"', resp.text, re.DOTALL)

            if not form_action:
                url_parsed = urlparse(resp.url)
                form_action_url = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}"
            else:
                form_action_url = form_action.group(1)

            return {
                'site_key': site_key.group(1),
                'form_action': form_action_url
            }

        except Exception as e:
            logging.error(f"Error extracting Cloudflare Turnstile data: {str(e)}")
            raise CloudflareTurnstileError(f"Error extracting Cloudflare Turnstile data: {str(e)}")

    def handle_Turnstile_Challenge(self, resp, **kwargs):
        try:
            if (
                not self.cloudscraper.captcha
                or not isinstance(self.cloudscraper.captcha, dict)
                or not self.cloudscraper.captcha.get('provider')
            ):
                self.cloudscraper.simpleException(
                    CloudflareCaptchaProvider,
                    "Cloudflare Turnstile detected, but no captcha provider configured"
                )

            turnstile_info = self.extract_turnstile_data(resp)

            time.sleep(self.delay)

            turnstile_response = Captcha.dynamicImport(
                self.cloudscraper.captcha.get('provider').lower()
            ).solveCaptcha(
                'turnstile',
                resp.url,
                turnstile_info['site_key'],
                self.cloudscraper.captcha
            )

            payload = {'cf-turnstile-response': turnstile_response}

            for field in re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', resp.text):
                if field[0] != 'cf-turnstile-response':
                    payload[field[0]] = field[1]

            url_parsed = urlparse(resp.url)
            challenge_url = turnstile_info['form_action']
            if not challenge_url.startswith('http'):
                challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_url}"

            cloudflare_kwargs = deepcopy(kwargs)
            cloudflare_kwargs['allow_redirects'] = False
            cloudflare_kwargs['headers'] = cloudflare_kwargs.get('headers', {})
            cloudflare_kwargs['headers'].update({
                'Origin': f'{url_parsed.scheme}://{url_parsed.netloc}',
                'Referer': resp.url,
                'Content-Type': 'application/x-www-form-urlencoded'
            })

            challenge_response = self.cloudscraper.request(
                'POST',
                challenge_url,
                data=payload,
                **cloudflare_kwargs
            )

            if challenge_response.status_code == 403:
                raise CloudflareSolveError("Failed to solve Cloudflare Turnstile challenge")

            return challenge_response

        except Exception as e:
            logging.error(f"Error handling Cloudflare Turnstile challenge: {str(e)}")
            raise CloudflareTurnstileError(f"Error handling Cloudflare Turnstile challenge: {str(e)}")
