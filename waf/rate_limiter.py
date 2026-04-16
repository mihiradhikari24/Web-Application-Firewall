import time
import threading


class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()

    def refill(self):
        now = time.time()
        elapsed = now - self.last_refill

        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.refill_rate
        )

        self.last_refill = now

    def consume(self, tokens=1):
        self.refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        return False


class RateLimiter:
    def __init__(self, config, ip_manager):
        self.lock = threading.Lock()
        self.ip_manager = ip_manager
        self.endpoint_limits = config["rate_limits"]
        self.buckets = {}
        self.recent_requests = {}
        self.last_cleanup = time.time()

    def _get_bucket(self, ip, endpoint):
        if ip not in self.buckets:
            self.buckets[ip] = {}

        cfg = self.endpoint_limits.get(endpoint)
        if not cfg:
            for key in self.endpoint_limits:
                if key != "default" and endpoint.startswith(key):
                    cfg = self.endpoint_limits[key]
                    break

        if not cfg:
            cfg = self.endpoint_limits["default"]

        #Adaptive capacity 
        attacks = self.ip_manager.suspicious.get(ip, {}).get("attacks", 0)

        base_capacity = cfg["limit"]
        capacity = max(5, base_capacity - attacks)

        refill_rate = base_capacity / cfg["window"]

        if endpoint not in self.buckets[ip]:
            self.buckets[ip][endpoint] = TokenBucket(capacity, refill_rate)

        bucket = self.buckets[ip][endpoint]

        bucket.capacity = capacity
        bucket.tokens = min(bucket.tokens, capacity)

        return bucket

    def _check_burst(self, ip):
        now = time.time()

        if ip not in self.recent_requests:
            self.recent_requests[ip] = []

        self.recent_requests[ip] = [
            t for t in self.recent_requests[ip]
            if now - t < 1
        ]

        self.recent_requests[ip].append(now)

        if len(self.recent_requests[ip]) > 10:
            self.ip_manager.record_attack(ip)
            return True

        return False

    def _cleanup(self):
        now = time.time()

        if now - self.last_cleanup < 60:
            return

        for ip in list(self.buckets.keys()):
            if ip not in self.ip_manager.suspicious and ip not in self.ip_manager.blacklist:
                del self.buckets[ip]
                self.recent_requests.pop(ip, None)

        self.last_cleanup = now

    def is_rate_limited(self, ip, endpoint):
        with self.lock:
            self._cleanup()

            if self._check_burst(ip):
                return True

            bucket = self._get_bucket(ip, endpoint)

            allowed = bucket.consume()

            return not allowed