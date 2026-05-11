# Requires Python 3.7+

import json
import platform
import ssl
import sys
from typing import List, Union

import requests
import urllib3

from . import __version__ as cloudscraper_version

def get_possible_ciphers() -> Union[List[str], str]:
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.set_ciphers('ALL')
        return sorted(cipher['name'] for cipher in context.get_ciphers())
    except AttributeError:
        return 'get_ciphers() is unsupported on this platform'

def _python_version() -> dict:
    interpreter = platform.python_implementation()
    version = platform.python_version()

    if interpreter == 'PyPy':
        vi = sys.pypy_version_info  # type: ignore[attr-defined]
        version = f'{vi.major}.{vi.minor}.{vi.micro}'
        if vi.releaselevel != 'final':
            version += vi.releaselevel

    return {'name': interpreter, 'version': version}

def system_info() -> dict:
    try:
        platform_info = {
            'system': platform.system(),
            'release': platform.release(),
        }
    except OSError:
        platform_info = {'system': 'Unknown', 'release': 'Unknown'}

    return {
        'platform': platform_info,
        'interpreter': _python_version(),
        'cloudscraper': cloudscraper_version,
        'js_engine': 'native (built-in)',
        'requests': requests.__version__,
        'urllib3': urllib3.__version__,
        'OpenSSL': {
            'version': ssl.OPENSSL_VERSION,
            'ciphers': get_possible_ciphers(),
        },
    }

systemInfo = system_info

if __name__ == '__main__':
    print(json.dumps(system_info(), indent=4))
