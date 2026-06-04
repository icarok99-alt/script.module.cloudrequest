# stealth.py

import random
import time
import logging
from collections import OrderedDict



class StealthMode:
    """
    A class to implement stealth techniques to avoid detection as a scraper
    """

    def __init__(self, cloudscraper):
        """
        Initialize the stealth mode

        :param cloudscraper: The CloudScraper instance
        """
        self.cloudscraper = cloudscraper
        self.request_count = 0
        self.last_request_time = 0
        self.human_like_delays = True
        self.randomize_headers = True
        self.browser_quirks = True


        self.min_delay = 0.5
        self.max_delay = 2.0



        self._chrome_ch_ua_variants = [
            '"Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"',
            '"Chromium";v="122", "Google Chrome";v="122", "Not-A.Brand";v="24"',
            '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            '"Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="24"',
            '"Chromium";v="128", "Google Chrome";v="128", "Not-A.Brand";v="99"',
            '"Chromium";v="130", "Google Chrome";v="130", "Not-A.Brand";v="99"',
            '"Chromium";v="131", "Google Chrome";v="131", "Not-A.Brand";v="24"',
            '"Chromium";v="132", "Google Chrome";v="132", "Not-A.Brand";v="99"',
            '"Chromium";v="133", "Google Chrome";v="133", "Not-A.Brand";v="24"',
            '"Chromium";v="134", "Google Chrome";v="134", "Not-A.Brand";v="99"',
            '"Chromium";v="135", "Google Chrome";v="135", "Not-A.Brand";v="8"',
            '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
        ]
        self.quirks = {
            'chrome': {
                'order': ['Host', 'Connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
                          'User-Agent', 'Accept', 'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-User',
                          'Sec-Fetch-Dest', 'Referer', 'Accept-Encoding', 'Accept-Language', 'Cookie'],
                'headers': {

                    'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-User': '?1',
                    'Sec-Fetch-Dest': 'document',
                    'Accept-Language': 'en-US,en;q=0.9'
                }
            },
            'firefox': {
                'order': ['Host', 'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
                          'Connection', 'Upgrade-Insecure-Requests', 'Sec-GPC', 'Referer', 'Cookie'],
                'headers': {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Upgrade-Insecure-Requests': '1',
                    'Connection': 'keep-alive',
                    'Sec-GPC': '1'
                }
            }
        }



    def apply_stealth_techniques(self, method, url, **kwargs):
        """
        Apply stealth techniques to the request

        :param method: HTTP method
        :param url: URL to request
        :param kwargs: Additional arguments for the request
        :return: Modified kwargs
        """

        if self.human_like_delays:
            self._apply_human_like_delay()


        if self.randomize_headers:
            kwargs = self._randomize_headers(kwargs)


        if self.browser_quirks:
            kwargs = self._apply_browser_quirks(kwargs)


        self.request_count += 1
        self.last_request_time = time.time()

        return kwargs



    def _apply_human_like_delay(self):
        """
        Add a random delay between requests to mimic human behavior
        """

        if self.request_count > 0:

            delay = random.uniform(self.min_delay, self.max_delay)


            if random.random() < 0.1:
                delay *= 1.5


            delay = min(delay, 10.0)


            if delay >= 0.1:
                logging.debug(f"Applying human-like delay of {delay:.2f} seconds")
                time.sleep(delay)



    def _randomize_headers(self, kwargs):
        """
        Randomize headers to avoid fingerprinting

        :param kwargs: Request kwargs
        :return: Modified kwargs with randomized headers
        """
        headers = kwargs.get('headers', {})




        if 'Accept' not in headers:
            accepts = [
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            ]
            headers['Accept'] = random.choice(accepts)


        if 'Accept-Language' not in headers:
            languages = [
                'en-US,en;q=0.9',
                'en-US,en;q=0.8',
                'en-GB,en;q=0.9,en-US;q=0.8',
                'en-CA,en;q=0.9,en-US;q=0.8',
                'en-AU,en;q=0.9,en-US;q=0.8'
            ]
            headers['Accept-Language'] = random.choice(languages)


        if random.random() < 0.5:
            headers['DNT'] = '1'

        kwargs['headers'] = headers
        return kwargs



    def _apply_browser_quirks(self, kwargs):
        """
        Apply browser-specific quirks to make requests look more authentic

        :param kwargs: Request kwargs
        :return: Modified kwargs with browser quirks
        """

        user_agent = kwargs.get('headers', {}).get('User-Agent', '')
        browser_type = 'chrome'

        if 'Firefox/' in user_agent:
            browser_type = 'firefox'
        elif 'Chrome/' in user_agent:
            browser_type = 'chrome'


        headers = kwargs.get('headers', {})


        if browser_type == 'chrome':
            import re as _re
            _m = _re.search(r'Chrome/(\d+)', user_agent)
            if _m:
                v = _m.group(1)
                self.quirks['chrome']['headers']['sec-ch-ua'] = (
                    f'"Chromium";v="{v}", "Google Chrome";v="{v}", "Not-A.Brand";v="99"'
                )
            else:
                self.quirks['chrome']['headers']['sec-ch-ua'] = random.choice(
                    self._chrome_ch_ua_variants
                )

        for header, value in self.quirks[browser_type]['headers'].items():
            if header not in headers:
                headers[header] = value


        if headers:
            ordered_headers = OrderedDict()

            for header in self.quirks[browser_type]['order']:
                if header in headers:
                    ordered_headers[header] = headers[header]

            for header, value in headers.items():
                if header not in ordered_headers:
                    ordered_headers[header] = value

            kwargs['headers'] = ordered_headers

        return kwargs



    def set_delay_range(self, min_delay, max_delay):
        """
        Set the range for random delays between requests

        :param min_delay: Minimum delay in seconds
        :param max_delay: Maximum delay in seconds
        """
        self.min_delay = min_delay
        self.max_delay = max_delay



    def enable_human_like_delays(self, enabled=True):
        """
        Enable or disable human-like delays between requests

        :param enabled: Whether to enable human-like delays
        """
        self.human_like_delays = enabled



    def enable_randomize_headers(self, enabled=True):
        """
        Enable or disable header randomization

        :param enabled: Whether to enable header randomization
        """
        self.randomize_headers = enabled



    def enable_browser_quirks(self, enabled=True):
        """
        Enable or disable browser quirks

        :param enabled: Whether to enable browser quirks
        """
        self.browser_quirks = enabled
