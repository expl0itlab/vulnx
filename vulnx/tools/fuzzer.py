import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from ..utils.helpers import Helpers

class Fuzzer:
    def __init__(self, rate_limit: float = 0.1):
        self.rate_limit = rate_limit
        self.helpers = Helpers()

    def fuzz_endpoints(self, base_url: str, wordlist: List[str], threads: int = 10) -> List[Dict[str, Any]]:
        discovered = []

        @Helpers.rate_limit(self.rate_limit)
        def check(endpoint):
            url = f"{base_url.rstrip('/')}/{endpoint}"
            try:
                r = requests.get(url, timeout=10, allow_redirects=False)
                if r.status_code not in (403, 404):
                    return {
                        "url": url,
                        "status_code": r.status_code,
                        "content_length": len(r.content)
                    }
            except requests.RequestException:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check, w) for w in wordlist]
            for f in as_completed(futures):
                result = f.result()
                if result:
                    discovered.append(result)

        return discovered
