# Requires Python 3.8+ (Kodi 19 / Matrix and above)

import json
import logging
import os
import ssl
import sys
import time
import copyreg

from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.sessions import Session

# ------------------------------------------------------------------------------- #

try:
    import brotli  # type: ignore[import]
except ImportError:
    brotli = None  # type: ignore[assignment]

# ------------------------------------------------------------------------------- #

from .exceptions import (
    CloudflareLoopProtection,
    CloudflareIUAMError,
    CloudflareChallengeError,
    CloudflareTurnstileError,
    CloudflareV3Error,
)

from .cloudflare import Cloudflare
from .cloudflare_v2 import CloudflareV2
from .cloudflare_v3 import CloudflareV3
from .turnstile import CloudflareTurnstile
from .user_agent import User_Agent
from .proxy_manager import ProxyManager
from .stealth import StealthMode
from .http_inspector import inspect_all as _inspect_all

# ------------------------------------------------------------------------------- #

__version__ = '3.0.0'

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------- #


class CipherSuiteAdapter(HTTPAdapter):

    __attrs__ = [
        'ssl_context',
        'max_retries',
        'config',
        '_pool_connections',
        '_pool_maxsize',
        '_pool_block',
        'source_address',
    ]

    def __init__(self, *args, **kwargs) -> None:
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite', None)
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')

        if self.source_address:
            if isinstance(self.source_address, str):
                self.source_address = (self.source_address, 0)
            if not isinstance(self.source_address, tuple):
                raise TypeError(
                    'source_address must be an IP address string or an (ip, port) tuple'
                )

        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.orig_wrap_socket = self.ssl_context.wrap_socket
            self.ssl_context.wrap_socket = self.wrap_socket

            if self.server_hostname:
                self.ssl_context.server_hostname = self.server_hostname

            self.ssl_context.set_ciphers(self.cipherSuite)
            self.ssl_context.set_ecdh_curve(self.ecdhCurve)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

        super().__init__(**kwargs)

    # ------------------------------------------------------------------------------- #

    def wrap_socket(self, *args, **kwargs):
        if getattr(self.ssl_context, 'server_hostname', None):
            kwargs['server_hostname'] = self.ssl_context.server_hostname
            self.ssl_context.check_hostname = False
        else:
            self.ssl_context.check_hostname = True
        return self.ssl_context.orig_wrap_socket(*args, **kwargs)

    # ------------------------------------------------------------------------------- #

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)

    # ------------------------------------------------------------------------------- #

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().proxy_manager_for(*args, **kwargs)


# ------------------------------------------------------------------------------- #


class CloudScraper(Session):

    def __init__(self, *args, **kwargs) -> None:
        self.debug: bool = kwargs.pop('debug', False)

        # Cloudflare challenge handling options
        self.disableCloudflareV1: bool = kwargs.pop('disableCloudflareV1', False)
        self.disableCloudflareV2: bool = kwargs.pop('disableCloudflareV2', False)
        self.disableCloudflareV3: bool = kwargs.pop('disableCloudflareV3', False)
        self.disableTurnstile: bool = kwargs.pop('disableTurnstile', False)
        self.delay: Optional[float] = kwargs.pop('delay', None)
        self.captcha: dict = kwargs.pop('captcha', {})
        self.doubleDown: bool = kwargs.pop('doubleDown', True)
        self.interpreter: str = kwargs.pop('interpreter', 'native')

        # Request hooks
        self.requestPreHook = kwargs.pop('requestPreHook', None)
        self.requestPostHook = kwargs.pop('requestPostHook', None)

        # TLS/SSL options
        self.cipherSuite = kwargs.pop('cipherSuite', None)
        self.ecdhCurve: str = kwargs.pop('ecdhCurve', 'prime256v1')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ssl_context = kwargs.pop('ssl_context', None)

        # Brotli decompression
        self.allow_brotli: bool = kwargs.pop('allow_brotli', brotli is not None)

        # User-Agent
        self.user_agent = User_Agent(
            allow_brotli=self.allow_brotli,
            browser=kwargs.pop('browser', None),
        )

        # Challenge solving depth
        self._solveDepthCnt: int = 0
        self.solveDepth: int = kwargs.pop('solveDepth', 3)

        # Session health monitoring (use monotonic for intervals, time() for timestamps)
        self.session_start_time: float = time.monotonic()
        self.request_count: int = 0
        self.last_403_time: float = 0.0
        self.session_refresh_interval: float = kwargs.pop('session_refresh_interval', 3600.0)
        self.auto_refresh_on_403: bool = kwargs.pop('auto_refresh_on_403', True)
        self.max_403_retries: int = kwargs.pop('max_403_retries', 3)
        self._403_retry_count: int = 0

        # Request throttling
        self.last_request_time: float = 0.0
        self.min_request_interval: float = kwargs.pop('min_request_interval', 1.0)
        self.max_concurrent_requests: int = kwargs.pop('max_concurrent_requests', 1)
        self.current_concurrent_requests: int = 0
        self.rotate_tls_ciphers: bool = kwargs.pop('rotate_tls_ciphers', True)
        self._cipher_rotation_count: int = 0

        # Proxy management
        proxy_options: dict = kwargs.pop('proxy_options', {})
        self.proxy_manager = ProxyManager(
            proxies=kwargs.pop('rotating_proxies', None),
            proxy_rotation_strategy=proxy_options.get('rotation_strategy', 'sequential'),
            ban_time=proxy_options.get('ban_time', 300),
        )

        # Stealth mode — pass options directly to the constructor
        stealth_options: dict = kwargs.pop('stealth_options', {})
        self.enable_stealth: bool = kwargs.pop('enable_stealth', True)
        self.stealth_mode = StealthMode(
            self,
            min_delay=stealth_options.get('min_delay', 0.5),
            max_delay=stealth_options.get('max_delay', 2.0),
            human_like_delays=stealth_options.get('human_like_delays', True),
            randomize_headers=stealth_options.get('randomize_headers', True),
            browser_quirks=stealth_options.get('browser_quirks', True),
        )

        # Initialise the parent Session
        super().__init__(*args, **kwargs)

        # Set up User-Agent and headers
        if 'requests' in self.headers.get('User-Agent', ''):
            self.headers = self.user_agent.headers
            if not self.cipherSuite:
                self.cipherSuite = self.user_agent.cipherSuite

        if isinstance(self.cipherSuite, list):
            self.cipherSuite = ':'.join(self.cipherSuite)

        # Mount the HTTPS adapter with our custom cipher suite
        self.mount(
            'https://',
            CipherSuiteAdapter(
                cipherSuite=self.cipherSuite,
                ecdhCurve=self.ecdhCurve,
                server_hostname=self.server_hostname,
                source_address=self.source_address,
                ssl_context=self.ssl_context,
            ),
        )

        # Initialise Cloudflare challenge handlers
        self.cloudflare_v1 = Cloudflare(self)
        self.cloudflare_v2 = CloudflareV2(self)
        self.cloudflare_v3 = CloudflareV3(self)
        self.turnstile = CloudflareTurnstile(self)

        # Allow pickle serialisation of ssl.SSLContext
        copyreg.pickle(ssl.SSLContext, lambda obj: (obj.__class__, (obj.protocol,)))

    # ------------------------------------------------------------------------------- #

    def __getstate__(self) -> dict:
        return self.__dict__

    # ------------------------------------------------------------------------------- #

    def perform_request(self, method: str, url: str, *args, **kwargs):
        """Allow subclasses to intercept the actual HTTP call."""
        return super().request(method, url, *args, **kwargs)

    # ------------------------------------------------------------------------------- #

    def simpleException(self, exception: type, msg: str) -> None:
        """Raise *exception* with *msg* and no stack trace."""
        self._solveDepthCnt = 0
        sys.tracebacklimit = 0
        raise exception(msg)

    # ------------------------------------------------------------------------------- #

    @staticmethod
    def debugRequest(req) -> None:
        try:
            print(_inspect_all(req).decode('utf-8', errors='backslashreplace'))
        except ValueError as exc:
            print(f'Debug Error: {getattr(exc, "message", exc)}')

    # ------------------------------------------------------------------------------- #

    def decodeBrotli(self, resp):
        """Manually decompress Brotli responses for older urllib3 versions."""
        if (
            requests.packages.urllib3.__version__ < '1.25.1'
            and resp.headers.get('Content-Encoding') == 'br'
        ):
            if self.allow_brotli and resp._content:
                resp._content = brotli.decompress(resp.content)
            else:
                logger.warning(
                    'Running urllib3 %s with Brotli content detected, '
                    'but allow_brotli is False — skipping decompression.',
                    requests.packages.urllib3.__version__,
                )
        return resp

    # ------------------------------------------------------------------------------- #

    def request(self, method: str, url: str, *args, **kwargs):
        # Throttle requests to avoid TLS fingerprint blocks
        self._apply_request_throttling()

        # Optionally rotate TLS cipher suites
        if self.rotate_tls_ciphers:
            self._rotate_tls_cipher_suite()

        # Refresh session if stale or flagged by recent 403s
        if self._should_refresh_session():
            self._refresh_session(url)

        # Proxy rotation
        if not kwargs.get('proxies') and self.proxy_manager._proxies:
            kwargs['proxies'] = self.proxy_manager.get_proxy()
        elif kwargs.get('proxies') and kwargs['proxies'] != self.proxies:
            self.proxies = kwargs['proxies']

        # Stealth techniques
        if self.enable_stealth:
            kwargs = self.stealth_mode.apply_stealth_techniques(method, url, **kwargs)
            # Mirror stealth headers back to session so plugins that read
            # scraper.headers (e.g. Abyss) still see the full header set.
            if 'headers' in kwargs:
                for _k, _v in kwargs['headers'].items():
                    self.headers.setdefault(_k, _v)

        self.request_count += 1
        self.current_concurrent_requests += 1

        # Pre-hook
        if self.requestPreHook:
            method, url, args, kwargs = self.requestPreHook(self, method, url, *args, **kwargs)

        # Perform the request
        try:
            response = self.decodeBrotli(self.perform_request(method, url, *args, **kwargs))
            if kwargs.get('proxies'):
                self.proxy_manager.report_success(kwargs['proxies'])
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError):
            if kwargs.get('proxies'):
                self.proxy_manager.report_failure(kwargs['proxies'])
            self.current_concurrent_requests = max(0, self.current_concurrent_requests - 1)
            raise
        except Exception:
            self.current_concurrent_requests = max(0, self.current_concurrent_requests - 1)
            raise

        # Debug logging
        if self.debug:
            self.debugRequest(response)

        # Post-hook
        if self.requestPostHook:
            new_response = self.requestPostHook(self, response)
            if response != new_response:
                response = new_response
                if self.debug:
                    print('==== requestPostHook Debug ====')
                    self.debugRequest(response)

        # ------------------------------------------------------------------------------- #
        # Cloudflare challenge detection
        # ------------------------------------------------------------------------------- #

        if self._solveDepthCnt >= self.solveDepth:
            depth = self._solveDepthCnt
            self.simpleException(
                CloudflareLoopProtection,
                f'Loop protection triggered after {depth} solve attempt(s).',
            )

        if not self.disableTurnstile and self.turnstile.is_Turnstile_Challenge(response):
            if self.debug:
                print('Detected a Cloudflare Turnstile challenge.')
            self._solveDepthCnt += 1
            response = self.turnstile.handle_Turnstile_Challenge(response, **kwargs)
            return response

        if not self.disableCloudflareV3 and self.cloudflare_v3.is_V3_Challenge(response):
            if self.debug:
                print('Detected a Cloudflare v3 JavaScript VM challenge.')
            self._solveDepthCnt += 1
            response = self.cloudflare_v3.handle_V3_Challenge(response, **kwargs)
            return response

        if not self.disableCloudflareV2:
            if self.cloudflare_v2.is_V2_Captcha_Challenge(response):
                self._solveDepthCnt += 1
                response = self.cloudflare_v2.handle_V2_Captcha_Challenge(response, **kwargs)
                return response
            if self.cloudflare_v2.is_V2_Challenge(response):
                self._solveDepthCnt += 1
                response = self.cloudflare_v2.handle_V2_Challenge(response, **kwargs)
                return response

        if not self.disableCloudflareV1 and self.cloudflare_v1.is_Challenge_Request(response):
            self._solveDepthCnt += 1
            response = self.cloudflare_v1.Challenge_Response(response, **kwargs)
            return response

        # ------------------------------------------------------------------------------- #
        # Post-challenge cleanup
        # ------------------------------------------------------------------------------- #

        if not response.is_redirect and response.status_code not in [429, 503]:
            self._solveDepthCnt = 0
            if response.status_code == 200 and not getattr(self, '_in_403_retry', False):
                self._403_retry_count = 0

        # Automatic session refresh on 403
        if response.status_code == 403 and self.auto_refresh_on_403:
            if self._403_retry_count < self.max_403_retries:
                self._403_retry_count += 1
                self.last_403_time = time.monotonic()

                if self.debug:
                    print(
                        f'Received 403, attempting session refresh '
                        f'(attempt {self._403_retry_count}/{self.max_403_retries})'
                    )

                if self._refresh_session(url):
                    if self.debug:
                        print('Session refreshed, retrying original request...')
                    self._in_403_retry = True
                    try:
                        retry_response = self.request(method, url, *args, **kwargs)
                        if retry_response.status_code == 200:
                            self._403_retry_count = 0
                        return retry_response
                    finally:
                        # Always clean up the retry flag
                        self.__dict__.pop('_in_403_retry', None)
                elif self.debug:
                    print('Session refresh failed, returning 403 response.')
            elif self.debug:
                print(f'Max 403 retries ({self.max_403_retries}) exceeded.')

        self.current_concurrent_requests = max(0, self.current_concurrent_requests - 1)
        return response

    # ------------------------------------------------------------------------------- #
    # Session health monitoring
    # ------------------------------------------------------------------------------- #

    def _should_refresh_session(self) -> bool:
        now = time.monotonic()
        if (now - self.session_start_time) > self.session_refresh_interval:
            return True
        if self.last_403_time > 0 and (now - self.last_403_time) < 60:
            return True
        return False

    def _refresh_session(self, url: str) -> bool:
        """Clear CF cookies, rotate User-Agent, and probe the base URL."""
        try:
            if self.debug:
                print('Refreshing session...')

            self._clear_cloudflare_cookies()
            self.session_start_time = time.monotonic()
            self.request_count = 0

            if hasattr(self, 'user_agent'):
                self.user_agent.loadUserAgent()
                self.headers.update(self.user_agent.headers)

            parsed = urlparse(url)
            base_url = f'{parsed.scheme}://{parsed.netloc}'

            test_response = super().get(base_url, timeout=30)
            success = test_response.status_code in [200, 301, 302, 304]

            if self.debug:
                status = 'successful' if success else f'failed (HTTP {test_response.status_code})'
                print(f'Session refresh {status}.')

            return success

        except Exception:
            logger.debug('Session refresh failed.', exc_info=True)
            return False

    def _clear_cloudflare_cookies(self) -> None:
        """Remove all known Cloudflare cookies from the session cookie jar."""
        cf_cookie_names = {
            'cf_clearance', 'cf_chl_2', 'cf_chl_prog',
            'cf_chl_rc_ni', 'cf_turnstile', '__cf_bm',
        }
        for domain in list(self.cookies.list_domains()):
            for name in cf_cookie_names:
                try:
                    self.cookies.clear(domain, '/', name)
                except Exception:
                    pass

        if self.debug:
            print('Cleared Cloudflare cookies.')

    # ------------------------------------------------------------------------------- #
    # Request throttling
    # ------------------------------------------------------------------------------- #

    def _apply_request_throttling(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            if self.debug:
                print(f'Request throttling: sleeping {sleep_time:.2f}s')
            time.sleep(sleep_time)

        while self.current_concurrent_requests >= self.max_concurrent_requests:
            if self.debug:
                print(
                    f'Concurrent request limit reached '
                    f'({self.current_concurrent_requests}/{self.max_concurrent_requests}), waiting...'
                )
            time.sleep(0.1)

        self.last_request_time = time.monotonic()

    # ------------------------------------------------------------------------------- #
    # TLS cipher rotation
    # ------------------------------------------------------------------------------- #

    def _rotate_tls_cipher_suite(self) -> None:
        if not hasattr(self, 'user_agent') or not hasattr(self.user_agent, 'cipherSuite'):
            return

        browser_name = getattr(self.user_agent, 'browser', 'chrome')

        try:
            browsers_file = os.path.join(
                os.path.dirname(__file__), 'user_agent', 'browsers.json'
            )
            with open(browsers_file, 'r', encoding='utf-8') as fh:
                browsers_data = json.load(fh)

            available_ciphers: List[str] = browsers_data.get('cipherSuite', {}).get(browser_name, [])

            if len(available_ciphers) <= 1:
                return

            self._cipher_rotation_count += 1
            cipher_index = self._cipher_rotation_count % len(available_ciphers)

            num_ciphers = min(8, len(available_ciphers))
            start_index = cipher_index % (len(available_ciphers) - num_ciphers + 1)
            selected_ciphers = available_ciphers[start_index : start_index + num_ciphers]

            new_suite = ':'.join(selected_ciphers)
            if new_suite == self.cipherSuite:
                return

            self.cipherSuite = new_suite
            self.mount(
                'https://',
                CipherSuiteAdapter(
                    cipherSuite=self.cipherSuite,
                    ecdhCurve=self.ecdhCurve,
                    server_hostname=self.server_hostname,
                    source_address=self.source_address,
                    ssl_context=self.ssl_context,
                ),
            )

            if self.debug:
                print(
                    f'Rotated TLS cipher suite (#{self._cipher_rotation_count}): '
                    f'{len(selected_ciphers)} ciphers from index {start_index}'
                )

        except Exception:
            logger.debug('TLS cipher rotation failed.', exc_info=True)

    # ------------------------------------------------------------------------------- #
    # Class-level convenience constructors
    # ------------------------------------------------------------------------------- #

    @classmethod
    def create_scraper(cls, sess=None, **kwargs) -> 'CloudScraper':
        """
        Create a ready-to-use CloudScraper session.

        Accepted keyword arguments (in addition to standard Session ones):
        - rotating_proxies, proxy_options (rotation_strategy, ban_time)
        - enable_stealth, stealth_options (min_delay, max_delay, human_like_delays,
          randomize_headers, browser_quirks)
        - session_refresh_interval, auto_refresh_on_403, max_403_retries
        - min_request_interval, max_concurrent_requests, rotate_tls_ciphers
        - disableCloudflareV1/V2/V3, disableTurnstile
        """
        scraper = cls(**kwargs)

        if sess:
            for attr in ['auth', 'cert', 'cookies', 'headers', 'hooks', 'params', 'proxies', 'data']:
                val = getattr(sess, attr, None)
                if val is not None:
                    setattr(scraper, attr, val)

        return scraper

    # ------------------------------------------------------------------------------- #

    @classmethod
    def get_tokens(cls, url: str, **kwargs) -> Tuple[Dict[str, str], str]:
        """Obtain Cloudflare clearance tokens and the User-Agent used."""
        _known_fields = {
            'allow_brotli', 'browser', 'debug', 'delay', 'doubleDown', 'captcha',
            'interpreter', 'source_address', 'requestPreHook', 'requestPostHook',
            'rotating_proxies', 'proxy_options', 'enable_stealth', 'stealth_options',
            'session_refresh_interval', 'auto_refresh_on_403', 'max_403_retries',
            'disableCloudflareV3', 'disableTurnstile',
        }
        scraper = cls.create_scraper(
            **{k: kwargs.pop(k) for k in list(kwargs) if k in _known_fields}
        )

        try:
            resp = scraper.get(url, **kwargs)
            resp.raise_for_status()
        except Exception:
            logger.exception('"%s" returned an error. Could not collect tokens.', url)
            raise

        domain = urlparse(resp.url).netloc
        cookie_domain = None

        for d in scraper.cookies.list_domains():
            if d.startswith('.') and d == f'.{domain}':
                cookie_domain = d
                break
        if cookie_domain is None:
            for d in scraper.cookies.list_domains():
                if d == domain:
                    cookie_domain = d
                    break

        if cookie_domain is None:
            cls.simpleException(
                scraper,
                CloudflareIUAMError,
                "Unable to find Cloudflare cookies. Is the site actually "
                "running Cloudflare IUAM (I'm Under Attack Mode)?",
            )

        cf_cookie_names = [
            'cf_clearance', 'cf_chl_2', 'cf_chl_prog', 'cf_chl_rc_ni', 'cf_turnstile'
        ]
        cf_cookies = {
            name: value
            for name in cf_cookie_names
            for value in [scraper.cookies.get(name, '', domain=cookie_domain)]
            if value
        }

        return cf_cookies, scraper.headers['User-Agent']

    # ------------------------------------------------------------------------------- #

    @classmethod
    def get_cookie_string(cls, url: str, **kwargs) -> Tuple[str, str]:
        """Return a ``Cookie`` header value string and the User-Agent used."""
        tokens, user_agent = cls.get_tokens(url, **kwargs)
        return '; '.join(f'{k}={v}' for k, v in tokens.items()), user_agent


# ------------------------------------------------------------------------------- #

if ssl.OPENSSL_VERSION_INFO < (1, 1, 1):
    logger.warning(
        'The OpenSSL used by this Python install (%s) is below the minimum supported '
        'version (>= 1.1.1) required to support TLS 1.3. '
        'You may encounter unexpected Captcha or Cloudflare 1020 blocks.',
        ssl.OPENSSL_VERSION,
    )

# ------------------------------------------------------------------------------- #
# Module-level aliases for convenience
# ------------------------------------------------------------------------------- #

create_scraper = CloudScraper.create_scraper
session = CloudScraper.create_scraper
get_tokens = CloudScraper.get_tokens
get_cookie_string = CloudScraper.get_cookie_string
