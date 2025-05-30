import requests, json, os, time

URL = "http://your.pihole.ip.here/api/"
PASSWORD = {"password": "pihole"}
SESSION_FILE = "session.json"

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
