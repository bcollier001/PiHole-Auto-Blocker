"""
Pi-hole Domain Categorizer & Auto-Blocker

This module automatically analyzes allowed domains using the Netify Informatics API
and blocks domains in undesired categories via Pi-hole's regex deny list.
"""
import os
import pickle
import re
import time

import requests

import pihole_api


### CONSTANTS ###
DOMAINS_FILE = "checked_domains.pkl"
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

### START Caching already checked domains ###

def load_checked_domains():
    """Load previously checked domains from pickle file."""
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, "rb") as f:
            return pickle.load(f)
    return set()

def save_checked_domains(checked_domains):
    """Save checked domains to pickle file."""
    with open(DOMAINS_FILE, "wb") as f:
        pickle.dump(checked_domains, f)

### END Caching already checked domains ###

### START Pi-Hole API Functions ###
def add_blocked_domain(domain_list: list[str], comment: str):
    """Add domains to Pi-hole's regex deny list."""
    sid = pihole_api.get_sid()
    headers = {"X-FTL-SID": sid}

    payload = {
        "domain": domain_list,
        "comment": comment,
        "enabled": True
    }

    response = requests.post(
        pihole_api.URL + "domains/deny/regex",
        json=payload,
        headers=headers,
        verify=False,
        timeout=30
    )
    return response.json()


def get_allowed_domains(from_time=None, until_time=None):
    """Get allowed domains from Pi-hole query log."""
    sid = pihole_api.get_sid()
    headers = {"X-FTL-SID": sid}

    if from_time is None:
        from_time = int(time.time() - 3600)
    if until_time is None:
        until_time = int(time.time())

    payload = {
        "from": from_time,
        "until": until_time,
        "length": -1,
    }

    response = requests.get(
        pihole_api.URL + "queries",
        params=payload,
        headers=headers,
        verify=False,
        timeout=30
    )
    data = response.json()

    domain_list = []

    for query in data.get("queries", []):
        if query["status"] != "GRAVITY":
            domain = ".".join(str(query["domain"]).split(".")[-2:]).lower()
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
        data = response.json()
    except requests.RequestException as e:
        print(f"[!] Failed to fetch category for domain {domain}: {e}")
        return None

    category_id = str(data.get("data", {}).get("category", {}).get("id"))

    already_checked_domains.add(domain)

    if category_id in BLOCKED_IDS:
        return rf"(.+\.|^){re.escape(domain)}$", BLOCKED_IDS[category_id]

    category_label = ALLOWED_IDS.get(category_id, "Unknown")

    if category_label == "Unknown":
        already_checked_domains.remove(domain)  # Does not cache unknown domains

    print(f"{domain} is {category_label}")

    return None


def process_domains(domain_list: list[str]):
    """Process a list of domains and block those in unwanted categories."""
    categorized_blocklist = {}

    for domain in sorted(set(domain_list)):
        result = check_domain_type(domain)
        if result:
            domain_name, category = result
            categorized_blocklist.setdefault(category, []).append(domain_name)

    # Push to Pi-hole API
    for category, domains_to_block in categorized_blocklist.items():
        print(f"[...] Blocking {len(domains_to_block)} domains under category: {category}")
        response: dict = add_blocked_domain(domains_to_block, comment=f"Auto-blocked: {category}")
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

while True:
    print("[*] Fetching domains from Pi-hole...")
    allowed_domains = get_allowed_domains()
    process_domains(allowed_domains)
    print("[✓] Sleeping for 59 Minutes...")
    time.sleep(3540)
