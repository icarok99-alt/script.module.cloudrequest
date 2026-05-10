# -*- coding: utf-8 -*-
# Requires Python 3.7+

"""
cloudscraper.exceptions
~~~~~~~~~~~~~~~~~~~~~~~
Set of exceptions raised by cloudscraper.
"""

# ------------------------------------------------------------------------------- #
# Cloudflare exceptions
# ------------------------------------------------------------------------------- #


class CloudflareException(Exception):
    """Base exception class for Cloudflare-related errors."""


class CloudflareLoopProtection(CloudflareException):
    """Raised when recursive challenge-solving depth is exceeded."""


class CloudflareCode1020(CloudflareException):
    """Raised when Cloudflare returns a Firewall block (Error 1020)."""


class CloudflareIUAMError(CloudflareException):
    """Raised when IUAM parameters cannot be extracted from the Cloudflare payload."""


class CloudflareChallengeError(CloudflareException):
    """Raised when a new/unsupported Cloudflare challenge type is detected."""


class CloudflareSolveError(CloudflareException):
    """Raised when a Cloudflare challenge cannot be solved."""


class CloudflareCaptchaError(CloudflareException):
    """Raised when Captcha parameters cannot be extracted from the Cloudflare payload."""


class CloudflareCaptchaProvider(CloudflareException):
    """Raised when no Captcha provider is configured but one is required."""


class CloudflareTurnstileError(CloudflareException):
    """Raised when the Cloudflare Turnstile challenge cannot be handled."""


class CloudflareV3Error(CloudflareException):
    """Raised when the Cloudflare v3 JavaScript VM challenge cannot be handled."""


# ------------------------------------------------------------------------------- #
# Captcha provider exceptions
# ------------------------------------------------------------------------------- #


class CaptchaException(Exception):
    """Base exception class for captcha provider errors."""


class CaptchaServiceUnavailable(CaptchaException):
    """Raised when an external captcha service cannot be reached."""


class CaptchaAPIError(CaptchaException):
    """Raised when the captcha provider API returns an error response."""


class CaptchaAccountError(CaptchaException):
    """Raised for captcha provider account-related problems (e.g. insufficient balance)."""


class CaptchaTimeout(CaptchaException):
    """Raised when the captcha provider takes too long to respond."""


class CaptchaParameter(CaptchaException):
    """Raised for bad or missing captcha parameters."""


class CaptchaBadJobID(CaptchaException):
    """Raised when the captcha provider returns an invalid job ID."""


class CaptchaReportError(CaptchaException):
    """Raised when the captcha provider is unable to accept a bad-solve report."""
