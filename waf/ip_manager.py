import json
import os
import time
import threading

IP_FILE = os.path.join(os.path.dirname(__file__), "../config/ip_lists.json")
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "../config/config.json")

def load_config():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

class IPManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.whitelist = set()
        self.blacklist = {}    
        self.suspicious = {}    
        self.last_load = 0
        config = load_config()
        self.reload_interval = max(300, min(config["ip_reload_interval"], 3600))
        self.min_interval = 300
        self.max_interval = 3600
        self.load()
        self.threshold = config["blacklist_threshold"]
        self.last_save = 0


    def load(self):
        try:
            with open(IP_FILE) as f:
                data = json.load(f)
            
            self.whitelist = set(data.get("whitelist", []))
            self.blacklist = data.get("blacklist", {})
            self.suspicious = data.get("suspicious", {})

            self.last_load = time.time()
        except Exception as e:
            print("IPManager load error:", e)
            self.whitelist = set()
            self.blacklist = {}
            self.suspicious = {}

    def save(self):
        with open(IP_FILE, "w") as f:
            json.dump({
                "whitelist": list(self.whitelist),
                "blacklist": self.blacklist,
                "suspicious": self.suspicious
            }, f, indent=2)
        
    def maybe_reload(self):
        now = time.time()

        if now - self.last_load > self.reload_interval:
            prev_snapshot = set(self.blacklist.keys())
            self.load()
            if set(self.blacklist.keys()) != prev_snapshot:
                self.reload_interval = max(self.min_interval, self.reload_interval - 600)
            else:
                self.reload_interval = min(self.max_interval, self.reload_interval + 300)

    def maybe_save(self):
        now = time.time()
        if now - self.last_save > 5:
            self.save()
            self.last_save = now

    def is_whitelisted(self, ip):
        return ip in self.whitelist

    def is_blacklisted(self, ip):
        return ip in self.blacklist

    def add_to_blacklist(self, ip):
        with self.lock:
            now = time.time()

            if ip in self.blacklist:
                self.blacklist[ip]["last_seen"] = now
                self.maybe_save()
                return

            self.blacklist[ip] = {
                "attacks": self.suspicious.get(ip, {}).get("attacks", 0),
                "last_seen": now
            }

            if ip in self.suspicious:
                del self.suspicious[ip]

            self.maybe_save()

    def add_to_whitelist(self, ip):
        with self.lock:
            self.whitelist.add(ip)
            self.save()

    def record_attack(self, ip):
        with self.lock:
            now = time.time()

            # skip whitelist
            if ip in self.whitelist:
                return

            # already blacklisted
            if ip in self.blacklist:
                self.blacklist[ip]["attacks"] += 1
                self.blacklist[ip]["last_seen"] = now
                self.maybe_save()
                return

            # suspicious tracking
            if ip not in self.suspicious:
                self.suspicious[ip] = {"attacks": 1, "last_seen": now}
            else:
                self.suspicious[ip]["attacks"] += 1
                self.suspicious[ip]["last_seen"] = now

            # threshold check
            if self.suspicious[ip]["attacks"] >= self.threshold:
                self.blacklist[ip] = self.suspicious.pop(ip)

            self.maybe_save()

    def cleanup(self):
        with self.lock:
            if not self.blacklist and not self.suspicious:
                return
            now = time.time()
            expiry = 30 * 24 * 60 * 60  # 30 days

            to_remove = []

            for ip, data in self.blacklist.items():
                if now - data["last_seen"] > expiry:
                    to_remove.append(ip)

            for ip, data in list(self.suspicious.items()):
                if now - data["last_seen"] > expiry:
                    del self.suspicious[ip]

            for ip in to_remove:
                del self.blacklist[ip]

            if to_remove:
                self.save()