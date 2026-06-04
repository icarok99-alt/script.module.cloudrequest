# cloudflare_v3.py



import re
import time
import json
import logging
import random
from copy import deepcopy
from collections import OrderedDict



try:
    from urlparse import urlparse, urljoin
except ImportError:
    from urllib.parse import urlparse, urljoin



from .exceptions import (
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
    CloudflareCaptchaError
)



from .interpreters import JavaScriptInterpreter as _JSI



class CloudflareV3():

    def __init__(self, cloudscraper):
        self.cloudscraper = cloudscraper
        self.delay = self.cloudscraper.delay or random.uniform(1.0, 5.0)





    @staticmethod
    def is_V3_Challenge(resp):
        try:
            return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [403, 429, 503]
                and (

                    re.search(
                        r'''cpo\.src\s*=\s*['"]/cdn-cgi/challenge-platform/\S+orchestrate/jsch/v3''',
                        resp.text,
                        re.M | re.S
                    ) or

                    re.search(
                        r'window\._cf_chl_ctx\s*=',
                        resp.text,
                        re.M | re.S
                    ) or

                    re.search(
                        r'<form[^>]*id="challenge-form"[^>]*action="[^"]*__cf_chl_rt_tk=',
                        resp.text,
                        re.M | re.S
                    )
                )
            )
        except AttributeError:
            pass

        return False





    def extract_v3_challenge_data(self, resp):
        try:

            challenge_ctx = re.search(
                r'window\._cf_chl_ctx\s*=\s*({.*?});',
                resp.text,
                re.DOTALL
            )

            if challenge_ctx:
                try:
                    ctx_data = json.loads(challenge_ctx.group(1))
                except json.JSONDecodeError:
                    ctx_data = {}
            else:
                ctx_data = {}


            challenge_opt = re.search(
                r'window\._cf_chl_opt\s*=\s*({.*?});',
                resp.text,
                re.DOTALL
            )

            if challenge_opt:
                try:
                    opt_data = json.loads(challenge_opt.group(1))
                except json.JSONDecodeError:
                    opt_data = {}
            else:
                opt_data = {}


            form_action = re.search(
                r'<form[^>]*id="challenge-form"[^>]*action="([^"]+)"',
                resp.text,
                re.DOTALL
            )

            if not form_action:
                raise CloudflareChallengeError("Could not find Cloudflare v3 challenge form")


            vm_script = re.search(
                r'<script[^>]*>\s*(.*?window\._cf_chl_enter.*?)</script>',
                resp.text,
                re.DOTALL
            )

            return {
                'ctx_data': ctx_data,
                'opt_data': opt_data,
                'form_action': form_action.group(1),
                'vm_script': vm_script.group(1) if vm_script else None
            }

        except Exception as e:
            logging.error(f"Error extracting Cloudflare v3 challenge data: {str(e)}")
            raise CloudflareChallengeError(f"Error extracting Cloudflare v3 challenge data: {str(e)}")





    def execute_vm_challenge(self, challenge_data, domain):
        try:
            if not challenge_data.get('vm_script'):

                return self.generate_fallback_response(challenge_data)


            vm_script = challenge_data['vm_script']


            js_context = f"""
            var window = {{
                location: {{
                    href: 'https://{domain}/',
                    hostname: '{domain}',
                    protocol: 'https:',
                    pathname: '/'
                }},
                navigator: {{
                    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    platform: 'Win32',
                    language: 'en-US',
                    languages: ['en-US', 'en'],
                    hardwareConcurrency: 8,
                    deviceMemory: 8,
                    maxTouchPoints: 0
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

            // Extract the challenge answer
            if (typeof window._cf_chl_answer !== 'undefined') {{
                window._cf_chl_answer;
            }} else if (typeof _cf_chl_answer !== 'undefined') {{
                _cf_chl_answer;
            }} else {{
                // Fallback calculation
                Math.random().toString(36).substring(2, 15);
            }}
            """


            try:
                engine = _JSI.dynamicImport('native')
                result = engine.eval(js_context, domain)

                return str(result) if result is not None else self.generate_fallback_response(challenge_data)

            except Exception as js_error:
                logging.warning(f"JavaScript execution failed: {str(js_error)}, using fallback")
                return self.generate_fallback_response(challenge_data)

        except Exception as e:
            logging.error(f"Error executing v3 VM challenge: {str(e)}")
            return self.generate_fallback_response(challenge_data)





    def generate_fallback_response(self, challenge_data):
        """Generate a fallback response when VM execution fails"""

        ctx_data = challenge_data.get('ctx_data', {})
        opt_data = challenge_data.get('opt_data', {})


        if 'chlPageData' in opt_data:

            page_data = opt_data['chlPageData']
            response = str(hash(page_data) % 1000000)
        elif 'cvId' in ctx_data:

            cv_id = ctx_data['cvId']
            response = str(hash(cv_id) % 1000000)
        else:

            response = str(random.randint(100000, 999999))

        return response





    def generate_v3_challenge_payload(self, challenge_data, resp, challenge_answer):
        try:

            r_token = re.search(r'name="r" value="([^"]+)"', resp.text)
            if not r_token:
                raise CloudflareChallengeError("Could not find 'r' token")


            form_fields = {}
            for field_match in re.finditer(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', resp.text):
                field_name, field_value = field_match.groups()
                if field_name not in ['jschl_answer']:
                    form_fields[field_name] = field_value


            payload = OrderedDict()
            payload['r'] = r_token.group(1)
            payload['jschl_answer'] = challenge_answer


            for field_name, field_value in form_fields.items():
                if field_name not in payload:
                    payload[field_name] = field_value

            return payload

        except Exception as e:
            logging.error(f"Error generating v3 challenge payload: {str(e)}")
            raise CloudflareChallengeError(f"Error generating v3 challenge payload: {str(e)}")





    def handle_V3_Challenge(self, resp, **kwargs):
        try:
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
                raise CloudflareSolveError("Failed to solve Cloudflare v3 challenge")

            return challenge_response

        except Exception as e:
            logging.error(f"Error handling Cloudflare v3 challenge: {str(e)}")
            raise CloudflareChallengeError(f"Error handling Cloudflare v3 challenge: {str(e)}")
