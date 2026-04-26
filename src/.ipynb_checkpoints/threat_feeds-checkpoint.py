import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import requests
import json
from datetime import datetime, timedelta

# ─── Known Malicious IPs (fallback if feeds are down) ──────────────────────────
STATIC_BLACKLIST = {
    "185.220.101.1", "185.220.101.2", "185.220.101.3",
    "198.96.155.3",  "198.96.155.4",  "171.25.193.20",
    "176.10.104.240","176.10.104.243","62.210.105.116",
}

FEED_URLS = {
    "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Abuse.ch Feodo"  : "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

# ─── Cache ─────────────────────────────────────────────────────────────────────
_cache = {
    "ips"        : set(),
    "last_update": None,
    "sources"    : []
}

def fetch_feed(name, url):
    """Fetch a single threat feed and return a set of IPs"""
    ips = set()
    try:
        response = requests.get(url, timeout=10)
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line.split()[0])  # take first token (the IP)
        print(f"  [{name}] Loaded {len(ips):,} IPs")
    except Exception as e:
        print(f"  [{name}] Failed: {e}")
    return ips


def load_feeds(force_refresh=False):
    """Load all threat feeds into cache (refresh every 6 hours)"""
    global _cache

    # Check if cache is still fresh
    if (not force_refresh
            and _cache["last_update"]
            and datetime.now() - _cache["last_update"] < timedelta(hours=6)):
        return _cache["ips"]

    print("Fetching threat intelligence feeds...")
    all_ips = set(STATIC_BLACKLIST)  # start with static list

    sources_loaded = ["Static Blacklist"]
    for name, url in FEED_URLS.items():
        fetched = fetch_feed(name, url)
        if fetched:
            all_ips.update(fetched)
            sources_loaded.append(name)

    _cache["ips"]         = all_ips
    _cache["last_update"] = datetime.now()
    _cache["sources"]     = sources_loaded

    print(f"Total blacklisted IPs: {len(all_ips):,}")
    print(f"Sources: {', '.join(sources_loaded)}")
    return all_ips


def check_ip(ip: str) -> dict:
    """
    Check if an IP is blacklisted.
    Returns a dict with keys: is_malicious, source, checked_at
    """
    blacklist = load_feeds()
    is_malicious = ip.strip() in blacklist

    return {
        "ip"          : ip,
        "is_malicious": is_malicious,
        "source"      : "Threat Intelligence Feed" if is_malicious else "Clean",
        "checked_at"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_feeds" : len(_cache["sources"]),
        "feed_size"   : len(blacklist)
    }


def get_feed_stats() -> dict:
    """Return current feed statistics"""
    blacklist = load_feeds()
    return {
        "total_ips"  : len(blacklist),
        "sources"    : _cache["sources"],
        "last_update": _cache["last_update"].strftime("%Y-%m-%d %H:%M:%S")
                       if _cache["last_update"] else "Never"
    }


if __name__ == "__main__":
    # Quick test
    test_ips = [
        "185.220.101.1",   # should be malicious
        "8.8.8.8",         # Google DNS — should be clean
        "192.168.1.1",     # local — should be clean
    ]

    print("\n===== IP Check Results =====")
    for ip in test_ips:
        result = check_ip(ip)
        status = "🚨 MALICIOUS" if result["is_malicious"] else "✅ CLEAN"
        print(f"  {ip:<20} {status}")
