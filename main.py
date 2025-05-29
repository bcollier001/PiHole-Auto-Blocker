import requests, json, os, time, pickle, re


### CONSTANTS ###
URL = "http://your.pihole.ip.here/api/"
PASSWORD = {"password": "pihole"}
SESSION_FILE = "session.json"
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

### START Persistent Session Functions ###

def get_sid():
    session_data = load_session()

    if is_session_valid(session_data):
        return session_data["sid"]
    
    #login
    response = requests.post(URL + "auth", json=PASSWORD, verify=False)

    data = response.json()
    sid = data.get("session", {}).get("sid")
    validity = data.get("session", {}).get("validity", 1800)
    if sid:
        save_session(sid, validity)
        return sid
    else:
        raise Exception("Failed to get SID")

def is_session_valid(session_data):
    return session_data and time.time() < session_data["expires_at"]

def load_session():
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, "r") as f:
        return json.load(f)
    
def save_session(sid, validity):
    session_data = {
        "sid" : sid,
        "expires_at": time.time() + validity
    }
    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f)

### END Persistent Session Functions ###

### START Caching already checked domains ###

def load_checked_domains():
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, "rb") as f:
            return pickle.load(f)
    return set()

def save_checked_domains(checked_domains):
    with open(DOMAINS_FILE, "wb") as f:
        pickle.dump(checked_domains, f)

### END Caching already checked domains ###

### START Pi-Hole API Functions ###
def add_blocked_domain(domains:list[str], comment:str):
    sid = get_sid()
    headers = {"X-FTL-SID": sid}

    payload = {
        "domain":domains,
        "comment":comment,
        "enabled":True
    }

    response = requests.post(URL+"domains/deny/regex", json=payload, headers=headers, verify=False)
    return response.json()


def get_allowed_domains(from_time=None,until_time=None):
    sid = get_sid()
    headers = {"X-FTL-SID": sid}

    if from_time is None:
        from_time = int(time.time() - 3600)
    if until_time is None:
        until_time = int(time.time())

    payload = {
        "from":from_time,
        "until":until_time,
        "length":-1,
    }

    response = requests.get(URL+"queries", params=payload, headers=headers, verify=False)
    data = response.json()

    allowed_domains = []

    for q in data.get("queries", []):
        if q["status"] != "GRAVITY":
            allowed_domains.append(".".join(str(q["domain"]).split(".")[-2:]).lower())
    
    return allowed_domains

### END Pi-Hole API Functions ###

already_checked_domains = load_checked_domains()

def check_domain_type(domain:str):
    
    if domain in already_checked_domains:
        return None

    try:
        response = requests.get("https://informatics.netify.ai/api/v2/lookup/domains/"+domain)
        data = response.json()
    except Exception as e:
        print(f"[!] Failed to fetch category for domain {domain}: {e}")
        return None

    category_id = str(data.get("data", {}).get("category", {}).get("id"))

    
    if category_id in BLOCKED_IDS:
        return rf"(.+\.|^){re.escape(domain)}$", BLOCKED_IDS[category_id]
    
    category_label = ALLOWED_IDS.get(category_id, "Unknown")

    if category_label != "Unknown":
        already_checked_domains.add(domain) #Does not cache unknown domains
    
    print(f"{domain} is {category_label}")
    
    return None

def process_domains(domains: list[str]):
    categorized_blocklist = {}

    for domain in sorted(set(domains)):
        result = check_domain_type(domain)
        if result:
            domain_name, category = result
            categorized_blocklist.setdefault(category, []).append(domain_name)
    
    # Push to Pi-hole API
    for category, domains in categorized_blocklist.items():
        print(f"[+] Blocking {len(domains)} domains under category: {category}")
        response = add_blocked_domain(domains, comment=f"Auto-blocked: {category}")
        print(f"[API] Response: {response}")

    # Save the updated domain cache
    save_checked_domains(already_checked_domains)

while True:
    print("[*] Fetching domains from Pi-hole...")
    domains = get_allowed_domains()
    process_domains(domains)
    print("[✓] Sleeping for 59 Minutes...")
    time.sleep(3540)
