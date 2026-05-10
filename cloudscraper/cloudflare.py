# Cloudflare V1
# Requires Python 3.7+

import html
import re
import time
import logging

from copy import deepcopy
from urllib.parse import urlparse, urljoin

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
from .interpreters import JavaScriptInterpreter

# ------------------------------------------------------------------------------- #

logger = logging.getLogger(__name__)


class Cloudflare:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper

    # ------------------------------------------------------------------------------- #
    # Unescape / decode html entities
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def unescape(html_text: str) -> str:
        return html.unescape(html_text)

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a valid Cloudflare challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_IUAM_Challenge(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [429, 503]
                and re.search(r'/cdn-cgi/images/trace/jsch/', resp.text, re.M | re.S)
                and re.search(
                    r'''<form .*?="challenge-form" action="/\S+__cf_chl_f_tk=''',
                    resp.text,
                    re.M | re.S,
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a new Cloudflare challenge
    # ------------------------------------------------------------------------------- #

    def is_New_IUAM_Challenge(self, resp) -> bool:
        try:
            return bool(
                self.is_IUAM_Challenge(resp)
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

    def is_New_Captcha_Challenge(self, resp) -> bool:
        try:
            return bool(
                self.is_Captcha_Challenge(resp)
                and re.search(
                    r'''cpo.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/(captcha|managed)/v1''',
                    resp.text,
                    re.M | re.S,
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a Cloudflare hCaptcha challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_Captcha_Challenge(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code == 403
                and re.search(
                    r'/cdn-cgi/images/trace/(captcha|managed)/', resp.text, re.M | re.S
                )
                and re.search(
                    r'''<form .*?="challenge-form" action="/\S+__cf_chl_f_tk=''',
                    resp.text,
                    re.M | re.S,
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Check if the response contains Firewall 1020 Error
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_Firewall_Blocked(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code == 403
                and re.search(
                    r'<span class="cf-error-code">1020</span>',
                    resp.text,
                    re.M | re.DOTALL,
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Wrapper for is_Captcha_Challenge, is_IUAM_Challenge, is_Firewall_Blocked
    # ------------------------------------------------------------------------------- #

    def is_Challenge_Request(self, resp) -> bool:
        if self.is_Firewall_Blocked(resp):
            self.cloudscraper.simpleException(
                CloudflareCode1020,
                'Cloudflare has blocked this request (Code 1020 Detected).',
            )

        if self.is_New_Captcha_Challenge(resp):
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                'Detected a Cloudflare version 2 Captcha challenge. '
                'This feature is not available in the open-source (free) version.',
            )

        if self.is_New_IUAM_Challenge(resp):
            self.cloudscraper.simpleException(
                CloudflareChallengeError,
                'Detected a Cloudflare version 2 challenge. '
                'This feature is not available in the open-source (free) version.',
            )

        if self.is_Captcha_Challenge(resp) or self.is_IUAM_Challenge(resp):
            if self.cloudscraper.debug:
                print('Detected a Cloudflare version 1 challenge.')
            return True

        return False

    # ------------------------------------------------------------------------------- #
    # Try to solve cloudflare javascript challenge.
    # ------------------------------------------------------------------------------- #

    def IUAM_Challenge_Response(self, body: str, url: str, interpreter: str) -> dict:
        try:
            form_payload = re.search(
                r'<form (?P<form>.*?="challenge-form" '
                r'action="(?P<challengeUUID>.*?'
                r'__cf_chl_f_tk=\S+)"(.*?)</form>)',
                body,
                re.M | re.DOTALL,
            )

            if not form_payload:
                self.cloudscraper.simpleException(
                    CloudflareIUAMError,
                    "Cloudflare IUAM detected, unfortunately we can't extract the parameters correctly.",
                )

            form_payload = form_payload.groupdict()

            if not all(key in form_payload for key in ['form', 'challengeUUID']):
                self.cloudscraper.simpleException(
                    CloudflareIUAMError,
                    "Cloudflare IUAM detected, unfortunately we can't extract the parameters correctly.",
                )

            payload = {}
            for challenge_param in re.findall(
                r'^\s*<input\s(.*?)/>', form_payload['form'], re.M | re.S
            ):
                input_payload = dict(re.findall(r'(\S+)="(\S+)"', challenge_param))
                if input_payload.get('name') in ['r', 'jschl_vc', 'pass']:
                    payload[input_payload['name']] = input_payload['value']

        except AttributeError:
            self.cloudscraper.simpleException(
                CloudflareIUAMError,
                "Cloudflare IUAM detected, unfortunately we can't extract the parameters correctly.",
            )

        host_parsed = urlparse(url)

        try:
            payload['jschl_answer'] = JavaScriptInterpreter.dynamicImport(
                interpreter
            ).solveChallenge(body, host_parsed.netloc)
        except Exception as exc:
            self.cloudscraper.simpleException(
                CloudflareIUAMError,
                f"Unable to parse Cloudflare anti-bots page: {getattr(exc, 'message', exc)}",
            )

        return {
            'url': (
                f"{host_parsed.scheme}://{host_parsed.netloc}"
                f"{self.unescape(form_payload['challengeUUID'])}"
            ),
            'data': payload,
        }

    # ------------------------------------------------------------------------------- #
    # Try to solve the Captcha challenge via 3rd party.
    # ------------------------------------------------------------------------------- #

    def captcha_Challenge_Response(
        self, provider: str, provider_params: dict, body: str, url: str
    ) -> dict:
        try:
            form_payload = re.search(
                r'<form (?P<form>.*?="challenge-form" '
                r'action="(?P<challengeUUID>.*?__cf_chl_captcha_tk__=\S+)"(.*?)</form>)',
                body,
                re.M | re.DOTALL,
            )

            if not form_payload:
                self.cloudscraper.simpleException(
                    CloudflareCaptchaError,
                    "Cloudflare Captcha detected, unfortunately we can't extract the parameters correctly.",
                )

            form_payload = form_payload.groupdict()

            if not all(key in form_payload for key in ['form', 'challengeUUID']):
                self.cloudscraper.simpleException(
                    CloudflareCaptchaError,
                    "Cloudflare Captcha detected, unfortunately we can't extract the parameters correctly.",
                )

            payload = dict(
                re.findall(
                    r'(name="r"\svalue|data-ray|data-sitekey|name="cf_captcha_kind"\svalue)="(.*?)"',
                    form_payload['form'],
                )
            )

            captcha_type = (
                'reCaptcha' if payload['name="cf_captcha_kind" value'] == 're' else 'hCaptcha'
            )

        except (AttributeError, KeyError):
            self.cloudscraper.simpleException(
                CloudflareCaptchaError,
                "Cloudflare Captcha detected, unfortunately we can't extract the parameters correctly.",
            )

        # ------------------------------------------------------------------------------- #
        # Pass proxy parameter to provider to solve captcha.
        # ------------------------------------------------------------------------------- #

        if (
            self.cloudscraper.proxies
            and self.cloudscraper.proxies != self.cloudscraper.captcha.get('proxy')
        ):
            # Bug fix: was incorrectly using `self.proxies` (undefined)
            self.cloudscraper.captcha['proxy'] = self.cloudscraper.proxies

        # ------------------------------------------------------------------------------- #
        # Pass User-Agent if provider supports it to solve captcha.
        # ------------------------------------------------------------------------------- #

        self.cloudscraper.captcha['User-Agent'] = self.cloudscraper.headers['User-Agent']

        # ------------------------------------------------------------------------------- #
        # Submit job to provider to request captcha solve.
        # ------------------------------------------------------------------------------- #

        captcha_response = Captcha.dynamicImport(provider.lower()).solveCaptcha(
            captcha_type,
            url,
            payload['data-sitekey'],
            provider_params,
        )

        # ------------------------------------------------------------------------------- #
        # Parse and handle the response of solved captcha.
        # ------------------------------------------------------------------------------- #

        data_payload = {
            'r': payload.get('name="r" value', ''),
            'cf_captcha_kind': payload['name="cf_captcha_kind" value'],
            'id': payload.get('data-ray'),
            'g-recaptcha-response': captcha_response,
        }

        if captcha_type == 'hCaptcha':
            data_payload['h-captcha-response'] = captcha_response

        host_parsed = urlparse(url)

        return {
            'url': (
                f"{host_parsed.scheme}://{host_parsed.netloc}"
                f"{self.unescape(form_payload['challengeUUID'])}"
            ),
            'data': data_payload,
        }

    # ------------------------------------------------------------------------------- #
    # Attempt to handle and send the challenge response back to Cloudflare
    # ------------------------------------------------------------------------------- #

    def Challenge_Response(self, resp, **kwargs):
        if self.is_Captcha_Challenge(resp):
            # Double down on the request as some websites only check
            # if cfuid is populated before issuing a Captcha.
            if self.cloudscraper.doubleDown:
                resp = self.cloudscraper.decodeBrotli(
                    self.cloudscraper.perform_request(resp.request.method, resp.url, **kwargs)
                )

            if not self.is_Captcha_Challenge(resp):
                return resp

            if (
                not self.cloudscraper.captcha
                or not isinstance(self.cloudscraper.captcha, dict)
                or not self.cloudscraper.captcha.get('provider')
            ):
                self.cloudscraper.simpleException(
                    CloudflareCaptchaProvider,
                    "Cloudflare Captcha detected, unfortunately you haven't loaded an "
                    "anti-Captcha provider correctly via the 'captcha' parameter.",
                )

            if self.cloudscraper.captcha.get('provider') == 'return_response':
                return resp

            submit_url = self.captcha_Challenge_Response(
                self.cloudscraper.captcha.get('provider'),
                self.cloudscraper.captcha,
                resp.text,
                resp.url,
            )
        else:
            # Cloudflare requires a delay before solving the challenge
            if not self.cloudscraper.delay:
                try:
                    delay = (
                        float(
                            re.search(
                                r'submit\(\);\r?\n\s*},\s*([0-9]+)',
                                resp.text,
                            ).group(1)
                        )
                        / 1000.0
                    )
                    if isinstance(delay, (int, float)):
                        self.cloudscraper.delay = delay
                except (AttributeError, ValueError):
                    self.cloudscraper.simpleException(
                        CloudflareIUAMError,
                        'Cloudflare IUAM possibly malformed, issue extracting delay value.',
                    )

            time.sleep(self.cloudscraper.delay)

            submit_url = self.IUAM_Challenge_Response(
                resp.text,
                resp.url,
                self.cloudscraper.interpreter,
            )

        # ------------------------------------------------------------------------------- #
        # Send the Challenge Response back to Cloudflare
        # ------------------------------------------------------------------------------- #

        if submit_url:

            def update_attr(obj: dict, name: str, new_value: dict) -> dict:
                obj.setdefault(name, {}).update(new_value)
                return obj[name]

            cloudflare_kwargs = deepcopy(kwargs)
            cloudflare_kwargs['allow_redirects'] = False
            cloudflare_kwargs['data'] = update_attr(
                cloudflare_kwargs, 'data', submit_url['data']
            )

            url_parsed = urlparse(resp.url)
            cloudflare_kwargs['headers'] = update_attr(
                cloudflare_kwargs,
                'headers',
                {
                    'Origin': f'{url_parsed.scheme}://{url_parsed.netloc}',
                    'Referer': resp.url,
                },
            )

            challenge_submit_response = self.cloudscraper.request(
                'POST',
                submit_url['url'],
                **cloudflare_kwargs,
            )

            if challenge_submit_response.status_code == 400:
                self.cloudscraper.simpleException(
                    CloudflareSolveError,
                    'Invalid challenge answer detected, Cloudflare broken?',
                )

            # Return response if Cloudflare is doing content pass-through instead of 3xx,
            # else follow redirect (handling scheme changes http → https).
            if not challenge_submit_response.is_redirect:
                return challenge_submit_response

            cloudflare_kwargs = deepcopy(kwargs)
            cloudflare_kwargs['headers'] = update_attr(
                cloudflare_kwargs,
                'headers',
                {'Referer': challenge_submit_response.url},
            )

            location = challenge_submit_response.headers['Location']
            redirect_location = (
                urljoin(challenge_submit_response.url, location)
                if not urlparse(location).netloc
                else location
            )

            return self.cloudscraper.request(
                resp.request.method,
                redirect_location,
                **cloudflare_kwargs,
            )

        # Shouldn't reach here — re-request original query and process again.
        return self.cloudscraper.request(resp.request.method, resp.url, **kwargs)
