"""
Pi-hole API interaction module for session management and authentication.
"""
import json
import os
import time

import requests

URL = os.getenv("PIHOLE_URL", "http://your.pihole.ip.here/api/")
PASSWORD = {"password": os.getenv("PIHOLE_PASSWORD")}
SESSION_FILE = "session.json"

# Validate requred environment variables
if not os.getenv("PIHOLE_PASSWORD"):
    raise ValueError("PIHOLE_PASSWORD environment variable is required")

### START Persistent Session Functions ###

def get_sid():
    """Get or refresh Pi-hole session ID."""
    session_data = load_session()

    if is_session_valid(session_data):
        return session_data["sid"]

    #login
    response = requests.post(URL + "auth", json=PASSWORD, verify=False, timeout=30)

    data = response.json()
    sid = data.get("session", {}).get("sid")
    validity = data.get("session", {}).get("validity", 1800)
    if sid:
        save_session(sid, validity)
        return sid

    raise ValueError("Failed to get SID")

def is_session_valid(session_data):
    """Check if session data is valid and not expired."""
    return session_data and time.time() < session_data["expires_at"]

def load_session():
    """Load session data from file."""
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_session(sid, validity):
    """Save session data to file."""
    session_data = {
        "sid" : sid,
        "expires_at": time.time() + validity
    }
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(session_data, f)

### END Persistent Session Functions ###
