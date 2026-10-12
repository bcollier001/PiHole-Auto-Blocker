# 🔒 Pi-hole Domain Categorizer & Auto-Blocker

This Python script enhances your [Pi-hole](https://pi-hole.net/) (v6+) setup by automatically analyzing allowed domains using the [Netify Informatics API](https://netify.ai/) and blocking domains in undesired categories (like Ads or Malware) via Pi-hole's regex deny list.

---

## ⚙️ Features

- 🔁 **Continuous Monitoring**: Polls Pi-hole's query log roughly every hour, picking up where the previous run ended so no queries are missed.
- 🔍 **Domain Categorization**: Uses Netify to determine each domain's category.
- 🛡️ **Auto-blocking**: Automatically regex-blocks domains identified as Ads or Malware.
- 🌐 **Public Suffix aware**: Domains are reduced to their registrable domain using the Public Suffix List (`ads.bbc.co.uk` → `bbc.co.uk`, `foo.github.io` stays `foo.github.io`), so a whole TLD like `co.uk` can never be blocked by mistake.
- 🧠 **Duplicate Filtering**: Avoids re-checking previously scanned domains. Blocked domains are only cached once Pi-hole has accepted them, so failed pushes are retried.
- 💾 **Persistent Caching**: Saves checked domains in `checked_domains.json` for reuse across runs.
- 🔐 **Session Persistence**: Reuses Pi-hole session tokens and logs in again automatically if a session expires early.
- 🩹 **Resilient**: Network errors are logged and retried on the next cycle instead of crashing the service.

---

## 📁 File Overview

- `main.py` – The core script.
- `pihole_api.py` – Pi-hole authentication and API helper.
- `session.json` – Stores your Pi-hole session token and expiration (created with `600` permissions).
- `checked_domains.json` – Tracks domains already processed.

> Upgrading from an older version? The old `checked_domains.pkl` cache is no longer read and can be deleted. Domains will simply be re-checked once.

---

## 🚀 Setup

1. **Install dependencies** (a virtual environment is required on Raspberry Pi OS Bookworm and newer):

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

2. **Configure environment variables**:

   Create a `.env` file in the project directory:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and update:

   ```bash
   PIHOLE_URL=http://your.pihole.address.here/api/
   PIHOLE_PASSWORD=your_pihole_password
   # true if Pi-hole uses HTTPS with a certificate this machine trusts
   PIHOLE_VERIFY_TLS=false
   ```

   Secure the file:
   ```bash
   chmod 600 .env
   ```

   `.env` is listed in `.gitignore`. Never commit it.

3. **Run manually**:

   ```bash
   # Export the variables in .env and run
   set -a; source .env; set +a
   .venv/bin/python main.py
   ```

4. **Install as systemd service**:

   The service file assumes the project lives in `/home/pi/PiHoleBlocker/` and runs as user `pi`. Edit `User`, `Group` and the paths in `pihole-auto-blocker.service` if your setup differs (newer Raspberry Pi OS images don't create a `pi` user by default).

   ```bash
   # Copy service file
   sudo cp pihole-auto-blocker.service /etc/systemd/system/

   # Enable and start service (Enable to run at Startup)
   sudo systemctl daemon-reload
   sudo systemctl enable pihole-auto-blocker.service
   sudo systemctl start pihole-auto-blocker.service

   # Check status
   sudo systemctl status pihole-auto-blocker.service
   ```

## 📊 Service Management

```bash
# View logs
sudo journalctl -u pihole-auto-blocker.service -f

# Stop service
sudo systemctl stop pihole-auto-blocker.service

# Restart service
sudo systemctl restart pihole-auto-blocker.service

# Disable service
sudo systemctl disable pihole-auto-blocker.service
```

---

## ✏️ Configuration

You can customize which categories are blocked or allowed by editing `main.py`:

```python
BLOCKED_IDS = {
    "3": "Ads",
    "16": "Malware"
}

ALLOWED_IDS = {
    "1": "Unclassified",
    "2": "Adult",
    ...
}
```

Category IDs are based on the Netify API schema.

---

## 🔐 Security & Privacy Notice

- The `.env` file should have restricted permissions (`600`).
- TLS certificate checks are off by default because Pi-hole ships with a self-signed certificate. If your Pi-hole uses HTTPS with a trusted certificate, set `PIHOLE_VERIFY_TLS=true`. With a plain `http://` URL, your Pi-hole password is sent unencrypted on your local network.
- Every allowed domain seen in your query log is sent to Netify's public API for categorization. Only registrable domain names are sent (no client IPs), but be aware that a third party sees which sites your network visits.

---

## 📦 Sample Output

```
[*] Fetching domains from Pi-hole...
example.com is Technology
[...] Blocking 3 domains under category: Ads

#####  Success  #####
[+] (.+\.|^)6sc\.co$
[+] (.+\.|^)akstat\.io$
[+] (.+\.|^)company\-target\.com$

[✓] Sleeping for 59 Minutes...
```

---

## 🔧 Future Improvements

- Add whitelist (never-block) support
- Configure blocked categories from `.env`
- Dry-run mode
- Log results to file

---

## 🙏 Credits

- [Pi-hole](https://pi-hole.net/)
- [Netify Informatics](https://informatics.netify.ai/)
- [tldextract](https://github.com/john-kurkowski/tldextract)

---

## 🛑 Disclaimer

This script is provided as-is. Blocking is based on category IDs and may affect access to legitimate services. Review categories carefully before use.
