"""
Pi-hole Domain Categorizer & Auto-Blocker

This module automatically analyzes allowed domains using the Netify Informatics API
and blocks domains in undesired categories via Pi-hole's regex deny list.
"""
import json
import os
import random
import re
import time

import requests
import tldextract

import pihole_api


### CONSTANTS ###
DOMAINS_FILE = "checked_domains.json"
# Categorized domains are re-checked monthly in case Netify reclassifies them
CACHE_SECONDS = 30 * 24 * 3600
# Domains Netify doesn't know yet are retried daily instead of every run
RETRY_SECONDS = 24 * 3600
RETRY_CATEGORIES = {"Not in Netify", "Unknown"}
SLEEP_SECONDS = 3540
# Pi-hole query statuses that mean the query was answered (not blocked)
ALLOWED_STATUSES = {"FORWARDED", "CACHE", "CACHE_STALE", "RETRIED", "RETRIED_DNSSEC"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")
# Uses the bundled Public Suffix List (no network, no cache dir), ICANN
# suffixes only, so "ads.bbc.co.uk" -> "bbc.co.uk" and
# "x.a.run.app" -> "run.app". Private entries (e.g. "a.run.app",
# "github.io") are ignored, as Netify only knows the registrable domain.
EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False
)
BLOCKED_IDS = {
    "3":"Ads",
    "16":"Malware"
    }
ALLOWED_IDS = {
    "1": "Unclassified",
    "2": "Adult",
    "4": "Arts and Entertainment",
    "5": "Business",
    "6": "Career and Education",
    "7": "Dating",
    "8": "Drugs",
    "9": "Financial",
    "10": "File Sharing",
    "11": "Gambling",
    "12": "Games",
    "13": "Government",
    "14": "Health",
    "15": "Mail",
    "17": "Messaging",
    "18": "News",
    "19": "Portal",
    "20": "Recreation",
    "21": "Reference",
    "22": "Science",
    "23": "Shopping",
    "24": "Social Media",
    "25": "Society",
    "26": "Sports",
    "27": "Technology",
    "28": "VPN and Proxy",
    "29": "Streaming Media",
    "30": "Cybersecurity",
    "31": "OS/Software Updates",
    "32": "VoIP/Conferencing",
    "33": "Device/IoT",
    "34": "Remote Desktop",
    "35": "CDN",
    "36": "Hosting",
    "37": "ISP/Telco"
    }
#################
#################

### START Caching already checked domains ###

def load_checked_domains():
    """Load previously checked domains from the JSON cache file."""
    if os.path.exists(DOMAINS_FILE):
        try:
            with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            print(f"[!] Could not read {DOMAINS_FILE}, starting fresh: {e}")
            return {}
        if isinstance(data, list):
            # Old format (plain list of domains). Spread their check times over
            # the last CACHE_SECONDS so they don't all expire on the same day.
            now = time.time()
            return {
                domain: {"category": None, "checked": int(now - random.uniform(0, CACHE_SECONDS))}
                for domain in data
            }
        return data
    return {}

def save_checked_domains(checked_domains: dict):
    """Drop expired entries and save the rest to the JSON cache file (atomically)."""
    now = time.time()
    for domain in [d for d, entry in checked_domains.items() if not is_fresh(entry, now)]:
        del checked_domains[domain]
    tmp_file = DOMAINS_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(checked_domains, f, indent=1, sort_keys=True)
    os.replace(tmp_file, DOMAINS_FILE)

def is_fresh(entry: dict, now: float):
    """True while a cache entry is younger than the TTL for its category."""
    ttl = RETRY_SECONDS if entry.get("category") in RETRY_CATEGORIES else CACHE_SECONDS
    return now < entry.get("checked", 0) + ttl

def is_cached(domain: str):
    """True if the domain was checked recently enough to skip Netify."""
    entry = already_checked_domains.get(domain)
    return entry is not None and is_fresh(entry, time.time())

def mark_checked(domain: str, category: str):
    """Record the domain's category and when it was checked."""
    already_checked_domains[domain] = {"category": category, "checked": int(time.time())}

### END Caching already checked domains ###

### START Pi-Hole API Functions ###
def add_blocked_domain(domain_list: list[str], comment: str):
    """Add domains to Pi-hole's regex deny list."""
    payload = {
        "domain": domain_list,
        "comment": comment,
        "enabled": True
    }
    return pihole_api.api_request("POST", "domains/deny/regex", json=payload)


def get_denied_regexes():
    """Get the regexes already on Pi-hole's regex deny list."""
    data = pihole_api.api_request("GET", "domains/deny/regex")
    return {entry.get("domain") for entry in data.get("domains", [])}


def get_allowed_domains(from_time, until_time):
    """Get registrable domains of allowed queries from the Pi-hole query log."""
    payload = {
        "from": from_time,
        "until": until_time,
        "length": -1,
    }
    data = pihole_api.api_request("GET", "queries", params=payload)

    domain_list = []

    for query in data.get("queries", []):
        if query.get("status") not in ALLOWED_STATUSES:
            continue
        domain = EXTRACT(str(query.get("domain", "")).lower()).top_domain_under_public_suffix
        # Skip reverse DNS lookups (e.g. 192.in-addr.arpa), Netify can't categorize them
        if domain and DOMAIN_RE.match(domain) and not domain.endswith(".arpa"):
            domain_list.append(domain)

    return domain_list

### END Pi-Hole API Functions ###

already_checked_domains = load_checked_domains()

def check_domain_type(domain: str):
    """Check domain category using Netify API and return regex if should be blocked."""
    if is_cached(domain):
        return None

    try:
        url = f"https://informatics.netify.ai/api/v2/lookup/domains/{domain}"
        response = requests.get(url, timeout=30)
        if response.status_code == 404:  # Not categorized yet, retried after RETRY_SECONDS
            print(f"{domain} is not in Netify")
            mark_checked(domain, "Not in Netify")
            return None
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as e:  # Not cached, retried next run
        print(f"[!] Failed to fetch category for domain {domain}: {e}")
        return None

    category = (data.get("data") or {}).get("category") or {}
    category_id = str(category.get("id"))

    if category_id in BLOCKED_IDS:
        # Cached only after Pi-hole accepts the block (see process_domains)
        return rf"(.+\.|^){re.escape(domain)}$", BLOCKED_IDS[category_id]

    category_label = ALLOWED_IDS.get(category_id, "Unknown")
    mark_checked(domain, category_label)

    print(f"{domain} is {category_label}")

    return None


def skip_already_blocked(categorized_blocklist: dict):
    """Drop regexes Pi-hole already has, it rejects duplicates (e.g. after the cache was reset)."""
    try:
        denied = get_denied_regexes()
    except (requests.RequestException, ValueError) as e:
        print(f"[!] Could not read Pi-hole's deny list: {e}")
        return
    for category, entries in categorized_blocklist.items():
        for domain, regex in entries:
            if regex in denied:
                print(f"[=] {domain} is already blocked")
                mark_checked(domain, category)
        categorized_blocklist[category] = [e for e in entries if e[1] not in denied]


def process_domains(domain_list: list[str]):
    """Process a list of domains and block those in unwanted categories."""
    categorized_blocklist = {}

    for domain in sorted(set(domain_list)):
        result = check_domain_type(domain)
        if result:
            regex, category = result
            categorized_blocklist.setdefault(category, []).append((domain, regex))

    if categorized_blocklist:
        skip_already_blocked(categorized_blocklist)

    # Push to Pi-hole API
    for category, entries in categorized_blocklist.items():
        if not entries:
            continue
        print(f"[...] Blocking {len(entries)} domains under category: {category}")
        try:
            response: dict = add_blocked_domain(
                [regex for _, regex in entries], comment=f"Auto-blocked: {category}"
            )
        except (requests.RequestException, ValueError) as e:
            print(f"[!] Failed to push {category} domains to Pi-hole, will retry next run: {e}")
            continue

        for domain, _ in entries:
            mark_checked(domain, category)
        errors = response.get("processed", {}).get("errors", [])
        successes = response.get("processed", {}).get("success", [])
        print()
        if len(successes) > 0:
            print("#" * 5, " Success ", "#" * 5)
            for success in successes:
                print(f"[+] {success['item']}")
            print()

        if len(errors) > 0:
            print("-" * 5, " Errors ", "-" * 5)
            for error in errors:
                print(f"[!] {error['item']}: {error['error']}")
            print()

    # Save the updated domain cache
    save_checked_domains(already_checked_domains)


def main():
    """Poll Pi-hole forever, picking up each run where the last one ended."""
    last_until = int(time.time()) - 3600
    while True:
        until_time = int(time.time())
        print("[*] Fetching domains from Pi-hole...")
        try:
            allowed_domains = get_allowed_domains(last_until, until_time)
            process_domains(allowed_domains)
            last_until = until_time
        except (requests.RequestException, ValueError) as e:
            print(f"[!] Run failed, will retry next cycle: {e}")
        print("[✓] Sleeping for 59 Minutes...")
        time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    main()
