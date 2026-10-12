"""
Pi-hole Domain Categorizer & Auto-Blocker

This module automatically analyzes allowed domains using the Netify Informatics API
and blocks domains in undesired categories via Pi-hole's regex deny list.
"""
import json
import os
import re
import time

import requests
import tldextract

import pihole_api


### CONSTANTS ###
DOMAINS_FILE = "checked_domains.json"
SLEEP_SECONDS = 3540
# Pi-hole query statuses that mean the query was answered (not blocked)
ALLOWED_STATUSES = {"FORWARDED", "CACHE", "CACHE_STALE", "RETRIED", "RETRIED_DNSSEC"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}$")
# Uses the bundled Public Suffix List (no network, no cache dir), so
# "ads.bbc.co.uk" -> "bbc.co.uk" and "foo.github.io" stays "foo.github.io"
EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
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
                return set(json.load(f))
        except (OSError, ValueError) as e:
            print(f"[!] Could not read {DOMAINS_FILE}, starting fresh: {e}")
    return set()

def save_checked_domains(checked_domains):
    """Save checked domains to the JSON cache file (atomically)."""
    tmp_file = DOMAINS_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(sorted(checked_domains), f, indent=0)
    os.replace(tmp_file, DOMAINS_FILE)

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
    if domain in already_checked_domains:
        return None

    try:
        url = f"https://informatics.netify.ai/api/v2/lookup/domains/{domain}"
        response = requests.get(url, timeout=30)
        if response.status_code == 404:  # Not categorized yet, re-checked next run
            print(f"{domain} is not in Netify")
            return None
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[!] Failed to fetch category for domain {domain}: {e}")
        return None

    category = (data.get("data") or {}).get("category") or {}
    category_id = str(category.get("id"))

    if category_id in BLOCKED_IDS:
        # Cached only after Pi-hole accepts the block (see process_domains)
        return rf"(.+\.|^){re.escape(domain)}$", BLOCKED_IDS[category_id]

    category_label = ALLOWED_IDS.get(category_id, "Unknown")

    if category_label != "Unknown":  # Does not cache unknown domains
        already_checked_domains.add(domain)

    print(f"{domain} is {category_label}")

    return None


def process_domains(domain_list: list[str]):
    """Process a list of domains and block those in unwanted categories."""
    categorized_blocklist = {}

    for domain in sorted(set(domain_list)):
        result = check_domain_type(domain)
        if result:
            regex, category = result
            categorized_blocklist.setdefault(category, []).append((domain, regex))

    # Push to Pi-hole API
    for category, entries in categorized_blocklist.items():
        print(f"[...] Blocking {len(entries)} domains under category: {category}")
        try:
            response: dict = add_blocked_domain(
                [regex for _, regex in entries], comment=f"Auto-blocked: {category}"
            )
        except (requests.RequestException, ValueError) as e:
            print(f"[!] Failed to push {category} domains to Pi-hole, will retry next run: {e}")
            continue

        already_checked_domains.update(domain for domain, _ in entries)
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
