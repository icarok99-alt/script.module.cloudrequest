# cloudscraper  –  main package  (v3.1.0)
# Requires Python 3.8+

import re
import time
import json
import logging
import hashlib
import random
from copy import deepcopy
from urllib.parse import urlparse

from .exceptions import (
    CloudflareIUAMError,
    CloudflareSolveError,
    CloudflareChallengeError,
)
from .interpreters import JavaScriptInterpreter as _JSI
from .challenge_detector import ChallengeType, detect_challenge_type

logger = logging.getLogger(__name__)

class CloudflareV3:

    def __init__(self, cloudscraper) -> None:
        self.cloudscraper = cloudscraper
        self.delay: float = self.cloudscraper.delay or random.uniform(2.0, 6.0)

    @staticmethod
    def is_V3_Challenge(resp) -> bool:
        try:
            return detect_challenge_type(resp) == ChallengeType.V3_JS
        except AttributeError:
            return False

    def extract_v3_challenge_data(self, resp) -> dict:
        
        def _try_json(match) -> dict:
            if not match:
                return {}
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                return {}

        ctx_data = _try_json(
            re.search(r"window\._cf_chl_ctx\s*=\s*({.*?});", resp.text, re.DOTALL)
        )
        opt_data = _try_json(
            re.search(r"window\._cf_chl_opt\s*=\s*({.*?});", resp.text, re.DOTALL)
        )

        form_action_match = (
            re.search(
                r'<form[^>]*id=["\']challenge-form["\'][^>]*action="([^"]*__cf_chl_rt_tk=[^"]+)"',
                resp.text,
                re.DOTALL,
            )
            or re.search(
                r'<form[^>]*action="([^"]*__cf_chl_rt_tk=[^"]+)"[^>]*id=["\']challenge-form["\']',
                resp.text,
                re.DOTALL,
            )
            or re.search(
                r'<form[^>]*id=["\']challenge-form["\'][^>]*action="([^"]+)"',
                resp.text,
                re.DOTALL,
            )
        )

        if not form_action_match:
            raise CloudflareChallengeError(
                "Could not find the V3 challenge form action."
            )

        vm_script_match = re.search(
            r"<script[^>]*>\s*((?:(?!</script>).)*?_cf_chl_enter(?:(?!</script>).)*?)</script>",
            resp.text,
            re.DOTALL,
        )

        form_body_match = re.search(
            r'<form[^>]*id=["\']challenge-form["\'][^>]*>(.*?)</form>',
            resp.text,
            re.DOTALL,
        )
        hidden_fields: dict = {}
        scope = form_body_match.group(1) if form_body_match else resp.text
        for attrs in re.findall(r"<input([^>]+)>", scope, re.IGNORECASE):
            name_m = re.search(r'name=["\']([^"\']+)["\']', attrs)
            val_m = re.search(r'value=["\']([^"\']*)["\']', attrs)
            if name_m:
                hidden_fields[name_m.group(1)] = val_m.group(1) if val_m else ""

        return {
            "ctx_data": ctx_data,
            "opt_data": opt_data,
            "form_action": form_action_match.group(1),
            "vm_script": vm_script_match.group(1) if vm_script_match else None,
            "hidden_fields": hidden_fields,
        }

    def execute_vm_challenge(self, challenge_data: dict, domain: str) -> str:
        
        vm_script = challenge_data.get("vm_script")
        if not vm_script:
            logger.debug("No VM script found in V3 page; using fallback response.")
            return self.generate_fallback_response(challenge_data)

        ctx_json = json.dumps(challenge_data.get("ctx_data", {}))
        opt_json = json.dumps(challenge_data.get("opt_data", {}))

        js_context = f

        try:
            engine = _JSI.dynamicImport(self.cloudscraper.interpreter)
            result = engine.eval(js_context, domain)
            if result is not None and str(result).strip():
                logger.debug("V3 VM execution succeeded: %s", result)
                return str(result)
        except Exception:
            logger.warning(
                "V3 JS VM execution failed; falling back to deterministic response.",
                exc_info=True,
            )

        return self.generate_fallback_response(challenge_data)

    def generate_fallback_response(self, challenge_data: dict) -> str:
        
        opt_data = challenge_data.get("opt_data", {})
        ctx_data = challenge_data.get("ctx_data", {})

        seed_parts = []
        for key in ("chlPageData", "cvId", "cNonce", "cZone", "cRay"):
            val = opt_data.get(key) or ctx_data.get(key)
            if val:
                seed_parts.append(str(val))

        if seed_parts:
            seed = "|".join(seed_parts)
            digest = hashlib.sha256(seed.encode()).hexdigest()
            return str(int(digest[:8], 16) % 10_000_000)

        hidden = challenge_data.get("hidden_fields", {})
        if hidden:
            seed = "|".join(f"{k}={v}" for k, v in sorted(hidden.items()))
            digest = hashlib.sha256(seed.encode()).hexdigest()
            return str(int(digest[:8], 16) % 10_000_000)

        logger.warning(
            "V3 fallback: no challenge seed data found; using placeholder answer."
        )
        return "0"

    def generate_v3_challenge_payload(
        self, challenge_data: dict, challenge_answer: str
    ) -> dict:
        
        hidden = challenge_data.get("hidden_fields", {})

        r_value = hidden.get("r", "")
        if not r_value:
            raise CloudflareChallengeError("Could not find the 'r' token in the V3 form.")

        payload: dict = {"r": r_value, "jschl_answer": challenge_answer}

        for k, v in hidden.items():
            if k != "jschl_answer":
                payload.setdefault(k, v)

        return payload

    def handle_V3_Challenge(self, resp, **kwargs):
        if self.cloudscraper.debug:
            print("Handling Cloudflare V3 JavaScript VM challenge.")

        challenge_info = self.extract_v3_challenge_data(resp)
        time.sleep(self.delay)

        url_parsed = urlparse(resp.url)
        challenge_answer = self.execute_vm_challenge(challenge_info, url_parsed.netloc)

        if self.cloudscraper.debug:
            print(f"V3 challenge answer: {challenge_answer}")

        payload = self.generate_v3_challenge_payload(challenge_info, challenge_answer)

        challenge_url = challenge_info["form_action"]
        if not challenge_url.startswith("http"):
            challenge_url = f"{url_parsed.scheme}://{url_parsed.netloc}{challenge_url}"

        cloudflare_kwargs = deepcopy(kwargs)
        cloudflare_kwargs["allow_redirects"] = False
        cloudflare_kwargs.setdefault("headers", {}).update(
            {
                "Origin": f"{url_parsed.scheme}://{url_parsed.netloc}",
                "Referer": resp.url,
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )

        challenge_response = self.cloudscraper.request(
            "POST", challenge_url, data=payload, **cloudflare_kwargs
        )

        if challenge_response.status_code == 403:
            raise CloudflareSolveError(
                "Failed to solve Cloudflare V3 challenge — server returned 403. "
                "A JavaScript interpreter may be required for this site."
            )

        return challenge_response
