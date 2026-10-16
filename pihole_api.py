"""
Pi-hole API interaction module for session management and authentication.
"""
import json
import os
import time

import requests
import urllib3

URL = os.getenv("PIHOLE_URL", "http://your.pihole.ip.here/api/").rstrip("/") + "/"
# Leave PIHOLE_PASSWORD empty if Pi-hole has no password set (no login needed)
PASSWORD = {"password": os.getenv("PIHOLE_PASSWORD", "")}
VERIFY_TLS = os.getenv("PIHOLE_VERIFY_TLS", "false").lower() in ("1", "true", "yes")
SESSION_FILE = "session.json"

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

### START Persistent Session Functions ###

def get_sid():
    """Get or refresh Pi-hole session ID."""
    session_data = load_session()

    if is_session_valid(session_data):
        return session_data["sid"]

    #login
    response = requests.post(URL + "auth", json=PASSWORD, verify=VERIFY_TLS, timeout=30)
    if response.status_code == 401:
        raise ValueError("Pi-hole rejected the password (check PIHOLE_PASSWORD)")
    response.raise_for_status()

    data = response.json()
    sid = data.get("session", {}).get("sid")
    validity = data.get("session", {}).get("validity", 1800)
    if sid:
        save_session(sid, validity)
        return sid

    raise ValueError("Failed to get SID")

def is_session_valid(session_data):
    """Check if session data is valid and not expired."""
    return session_data and time.time() < session_data.get("expires_at", 0)

def load_session():
    """Load session data from file."""
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

def save_session(sid, validity):
    """Save session data to file, readable only by the owner."""
    session_data = {
        "sid" : sid,
        "expires_at": time.time() + validity
    }
    fd = os.open(SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(session_data, f)
    os.chmod(SESSION_FILE, 0o600)

def clear_session():
    """Forget the saved session so the next call logs in again."""
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)

### END Persistent Session Functions ###

def api_request(method: str, endpoint: str, **kwargs):
    """Call the Pi-hole API, logging in again once if the session was rejected."""
    def send():
        headers = {"X-FTL-SID": get_sid()} if PASSWORD["password"] else {}
        return requests.request(
            method,
            URL + endpoint,
            headers=headers,
            verify=VERIFY_TLS,
            timeout=30,
            **kwargs
        )

    response = send()
    if response.status_code == 401:
        if not PASSWORD["password"]:
            raise ValueError("Pi-hole requires a password; set PIHOLE_PASSWORD in .env")
        clear_session()
        response = send()
    if not response.ok:
        # Pi-hole explains failures in {"error": {"message": ..., "hint": ...}}
        try:
            error = response.json().get("error") or {}
        except ValueError:
            error = {}
        detail = ": ".join(filter(None, (error.get("message"), error.get("hint"))))
        if detail:
            raise requests.HTTPError(
                f"{response.status_code} {response.reason}: {detail}", response=response
            )
    response.raise_for_status()
    return response.json()
