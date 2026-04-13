import time
import threading
from ip_manager import IPManager

ip_manager = IPManager()

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity          # max tokens
        self.tokens = capacity
        self.refill_rate = refill_rate    # tokens per second
        self.last_refill = time.time()

    def refill(self):
        now = time.time()
        elapsed = now - self.last_refill

        refill_amount = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + refill_amount)

        self.last_refill = now

    def consume(self, tokens=1):
        self.refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False


class RateLimiter:
    def __init__(self, config):
        self.lock = threading.Lock()

        self.default_limit = config["rate_limits"]["default"]["limit"]
        self.default_window = config["rate_limits"]["default"]["window"]

        self.endpoint_limits = config["rate_limits"]

        # ip → endpoint → bucket
        self.buckets = {}

    def _get_bucket(self, ip, endpoint):
        if ip not in self.buckets:
            self.buckets[ip] = {}

        if endpoint not in self.buckets[ip]:
            cfg = self.endpoint_limits.get(endpoint, self.endpoint_limits["default"])
            attacks = ip_manager.suspicious[ip]["attacks"]
            
            capacity = cfg["limit"]
            capacity = max(5, capacity - attacks)
            refill_rate = cfg["limit"] / cfg["window"]

            self.buckets[ip][endpoint] = TokenBucket(capacity, refill_rate)

        return self.buckets[ip][endpoint]

    def is_rate_limited(self, ip, endpoint):
        with self.lock:
            bucket = self._get_bucket(ip, endpoint)

            allowed = bucket.consume()

            return not allowed