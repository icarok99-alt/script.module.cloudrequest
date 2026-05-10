# Cloudflare V3 JavaScript VM Challenge Handler
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
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError,
)

# ------------------------------------------------------------------------------- #

from .interpreters import JavaScriptInterpreter as _JSI

# ------------------------------------------------------------------------------- #

logger = logging.getLogger(__name__)


class CloudflareV3:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(1.0, 5.0)

    # ------------------------------------------------------------------------------- #
    # Check if the response contains a Cloudflare v3 JavaScript VM challenge
    # ------------------------------------------------------------------------------- #

    @staticmethod
    def is_V3_Challenge(resp) -> bool:
        try:
            return bool(
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [403, 429, 503]
                and (
                    re.search(
                        r'''cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/jsch/v3''',
                        resp.text,
                        re.M | re.S,
                    )
                    or re.search(
                        r'window\._cf_chl_ctx\s*=',
                        resp.text,
                        re.M | re.S,
                    )
                    or re.search(
                        r'<form[^>]*id="challenge-form"[^>]*action="[^"]*__cf_chl_rt_tk=',
                        resp.text,
                        re.M | re.S,
                    )
                )
            )
        except AttributeError:
            return False

    # ------------------------------------------------------------------------------- #
    # Extract v3 challenge data from the page
    # ------------------------------------------------------------------------------- #

    def extract_v3_challenge_data(self, resp) -> dict:
        def _try_json(match) -> dict:
            if not match:
                return {}
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                return {}

        ctx_data = _try_json(
            re.search(r'window\._cf_chl_ctx\s*=\s*({.*?});', resp.text, re.DOTALL)
        )
        opt_data = _try_json(
            re.search(r'window\._cf_chl_opt\s*=\s*({.*?});', resp.text, re.DOTALL)
        )

        form_action = re.search(
            r'<form[^>]*id="challenge-form"[^>]*action="([^"]+)"',
            resp.text,
            re.DOTALL,
        )
        if not form_action:
            raise CloudflareChallengeError('Could not find Cloudflare v3 challenge form')

        vm_script = re.search(
            r'<script[^>]*>\s*(.*?window\._cf_chl_enter.*?)</script>',
            resp.text,
            re.DOTALL,
        )

        return {
            'ctx_data': ctx_data,
            'opt_data': opt_data,
            'form_action': form_action.group(1),
            'vm_script': vm_script.group(1) if vm_script else None,
        }

    # ------------------------------------------------------------------------------- #
    # Execute JavaScript VM challenge
    # ------------------------------------------------------------------------------- #

    def execute_vm_challenge(self, challenge_data: dict, domain: str) -> str:
        vm_script = challenge_data.get('vm_script')

        if not vm_script:
            return self.generate_fallback_response(challenge_data)

        js_context = f"""
        var window = {{
            location: {{
                href: 'https://{domain}/',
                hostname: '{domain}',
                protocol: 'https:',
                pathname: '/'
            }},
            navigator: {{
                userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                platform: 'Win32',
                language: 'en-US'
            }},
            document: {{
                getElementById: function(id) {{
                    return {{ value: '', style: {{}} }};
                }},
                createElement: function(tag) {{
                    return {{
                        firstChild: {{ href: 'https://{domain}/' }},
                        style: {{}}
                    }};
                }}
            }},
            _cf_chl_ctx: {json.dumps(challenge_data.get('ctx_data', {}))},
            _cf_chl_opt: {json.dumps(challenge_data.get('opt_data', {}))},
            _cf_chl_enter: function() {{ return true; }}
        }};

        var document = window.document;
        var location = window.location;
        var navigator = window.navigator;

        {vm_script}

        if (typeof window._cf_chl_answer !== 'undefined') {{
            window._cf_chl_answer;
        }} else if (typeof _cf_chl_answer !== 'undefined') {{
            _cf_chl_answer;
        }} else {{
            Math.random().toString(36).substring(2, 15);
        }}
        """

        try:
            engine = _JSI.dynamicImport('native')
            result = engine.eval(js_context, domain)
            return str(result) if result is not None else self.generate_fallback_response(challenge_data)
        except Exception:
            logger.warning('JavaScript execution failed, using fallback response', exc_info=True)
            return self.generate_fallback_response(challenge_data)

    # ------------------------------------------------------------------------------- #
    # Generate fallback response for v3 challenges
    # ------------------------------------------------------------------------------- #

    def generate_fallback_response(self, challenge_data: dict) -> str:
        """Return a plausible answer when JS VM execution is unavailable."""
        opt_data = challenge_data.get('opt_data', {})
        ctx_data = challenge_data.get('ctx_data', {})

        if 'chlPageData' in opt_data:
            return str(hash(opt_data['chlPageData']) % 1_000_000)
        if 'cvId' in ctx_data:
            return str(hash(ctx_data['cvId']) % 1_000_000)
        return str(random.randint(100_000, 999_999))

    # ------------------------------------------------------------------------------- #
    # Generate v3 challenge payload
    # ------------------------------------------------------------------------------- #

    def generate_v3_challenge_payload(
        self, challenge_data: dict, resp, challenge_answer: str
    ) -> dict:
        r_token = re.search(r'name="r" value="([^"]+)"', resp.text)
        if not r_token:
            raise CloudflareChallengeError("Could not find 'r' token")

        # Collect all form fields except the answer placeholder
        form_fields = {
            name: value
            for name, value in re.findall(
                r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', resp.text
            )
            if name != 'jschl_answer'
        }

        payload = {'r': r_token.group(1), 'jschl_answer': challenge_answer}
        # Merge remaining fields without overwriting already-set keys
        payload.update({k: v for k, v in form_fields.items() if k not in payload})

        return payload

    # ------------------------------------------------------------------------------- #
    # Handle the Cloudflare v3 JavaScript VM challenge
    # ------------------------------------------------------------------------------- #

    def handle_V3_Challenge(self, resp, **kwargs):
        if self.cloudscraper.debug:
            print('Handling Cloudflare v3 JavaScript VM challenge.')

        challenge_info = self.extract_v3_challenge_data(resp)

        time.sleep(self.delay)

        url_parsed = urlparse(resp.url)
        challenge_answer = self.execute_vm_challenge(challenge_info, url_parsed.netloc)

        payload = self.generate_v3_challenge_payload(challenge_info, resp, challenge_answer)

        challenge_url = challenge_info['form_action']
        if not challenge_url.startswith('http'):
            challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_url}"

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
            raise CloudflareSolveError('Failed to solve Cloudflare v3 challenge')

        return challenge_response
