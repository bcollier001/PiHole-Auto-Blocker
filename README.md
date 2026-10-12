# 🔒 Pi-hole Domain Categorizer & Auto-Blocker

This Python script enhances your [Pi-hole](https://pi-hole.net/) setup by automatically analyzing allowed domains using the [Netify Informatics API](https://netify.ai/) and blocking domains in undesired categories (like Ads or Malware) via Pi-hole's regex deny list.

---

## ⚙️ Features

- 🔁 **Real-Time Monitoring**: Polls Pi-hole's query log every 60 minutes.
- 🔍 **Domain Categorization**: Uses Netify to determine the domain's category.
- 🛡️ **Auto-blocking**: Automatically regex-blocks domains identified as Ads or Malware.
- 🧠 **Duplicate Filtering**: Avoids re-checking previously scanned domains.
- 💾 **Persistent Caching**: Saves checked domains in a `.pkl` file for reuse across runs.
- 🔐 **Session Persistence**: Reuses Pi-hole session tokens to minimize re-authentication.
- 🧼 **Regex Escaping**: Ensures blocked domains are safely formatted.

---

## 📁 File Overview

- `main.py` – The core script.
- `session.json` – Stores your Pi-hole session token and expiration.
- `checked_domains.pkl` – Tracks domains already processed.

---

## 🚀 Setup

1. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
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
   ```

   Secure the file:
   ```bash
   chmod 600 .env
   ```

3. **Run manually**:

   ```bash
   # Load environment variables and run
   source .env && python main.py
   ```

4. **Install as systemd service**:

   ```bash
   # Copy service file
   sudo cp pihole-auto-blocker.service /etc/systemd/system/
   
   # Enable and start service (Enable to run at Startup)
   sudo systemctl daemon-reload
   sudo systemctl enable pihole-auto-blocker.service
   sudo systemctl start pihole-auto-blocker.service
   
   # Check stauts
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

You can customize which categories are blocked or allowed by editing:

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

## 🔐 Security Notice

- The `.env` file should have restricted permissions (600)
- `verify=False` is used to skip SSL checks. Change this if you use HTTPS with valid certs.

---

## 📦 Sample Output

```
[*] Fetching domains from Pi-hole...
tracking.example.com is Ads
[*] Blocking 3 domains under category: Ads

#####  Success  #####
[+] (.+\.|^)6sc\.co$
[+] (.+\.|^)akstat\.io$
[+] (.+\.|^)company\-target\.com$
[✓] Sleeping for 59 minutes...
```

---

## 🔧 Future Improvements

- Use `.env` for configuration
- Add whitelist support
- Log results to file
- Add CLI arguments or GUI

---

## 🙏 Credits

- [Pi-hole](https://pi-hole.net/)
- [Netify Informatics](https://informatics.netify.ai/)

---

## 🛑 Disclaimer

This script is provided as-is. Blocking is based on category IDs and may affect access to legitimate services. Review categories carefully before use.
