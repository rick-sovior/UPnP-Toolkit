# 🧪 Credential Harvester & UPnP Lab Toolkit

[![Python 3](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![Bash](https://img.shields.io/badge/Bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-Educational%20Use%20Only-yellow.svg)]()

> **⚠️ IMPORTANT DISCLAIMER**  
> These tools are designed **exclusively for authorised security testing in controlled lab environments**.  
> You must own the target devices or have explicit written permission.  
> **Unauthorised use is illegal** and may violate laws in your jurisdiction.

---

## 📖 Overview

This repository contains two tools originally built for quick-and‑dirty red‑team assessments, but they have been **completely overhauled** into a professional, feature‑rich lab suite:

- **`server.py`** – a credential‑harvesting HTTP server that serves a fake login page and logs POSTed credentials.
- **`hack.sh`** – a multi‑purpose UPnP and MITM automation script that can manipulate NAT rules, perform ARP spoofing, and hijack DNS.

The **new versions** are the result of a major rewrite – they are safer, more flexible, production‑ready for lab use, and include extensive error handling, logging, and validation.

---

## 🔄 Old vs New – What's Changed?

### `server.py` – The Credential Harvester

| Feature | Old Version | New Version (Improved) |
|---------|-------------|------------------------|
| **Port binding** | Hardcoded `PORT = 80` (requires root) | Configurable via `-p`; auto‑detects default IP |
| **Concurrency** | Single‑threaded (handles one request at a time) | **Multi‑threaded** (`ThreadingHTTPServer`) – handles many victims concurrently |
| **Logging** | Only printed to stdout on capture | **Structured logging** – writes to a file (`credentials.log`) with timestamps and client IPs |
| **Custom HTML** | HTML hardcoded in the script | Supports **external HTML files** (`--html`) – change the page without editing code |
| **Command‑line interface** | None – had to edit the script to change port | Full **argparse** – `-H`, `-p`, `-l`, `--html`, with auto‑help |
| **Error handling** | Minimal, often crashed on malformed requests | Comprehensive – handles empty bodies, 404, 500, and Permission/port‑in‑use errors gracefully |
| **IPv4 detection** | None | Auto‑detects the default interface IP (`get_default_ip()`) |
| **HTTP status codes** | Only 200 or 302 | Proper 404, 400, 500 responses with logging |

**Why it matters**:  
The new `server.py` is a **professional‑grade tool** – you can run it on any port, serve any phishing page, log everything to a file, and handle hundreds of simultaneous connections without dropping a single credential.

---

### `hack.sh` – The UPnP & MITM Toolkit

| Feature | Old Version | New Version (Improved) |
|---------|-------------|------------------------|
| **Configuration** | 4 hardcoded variables (ROUTER, ATTACKER, VICTIM, SPOOF_DOMAIN) – had to edit the script for each use | **Environment variables** + command‑line arguments (`-r`, `-a`, `-v`, `-p`) – no script editing required |
| **Commands** | Only 4: `backdoor`, `list`, `delete`, `hijack` | **13+ commands** – `status`, `discover`, `list`, `add`, `delete`, `test‑description`, `watch`, `mitm`, `dns‑hijack`, and more |
| **Error handling** | None – failures were silent or crashed | **Full validation** – checks IP/port formats, confirms reachability, handles curl/HTTP errors with clear messages |
| **Logging** | No persistent logging | **Logs every action** to `upnp_lab.log` with timestamps |
| **Safety prompts** | No confirmation – dangerous actions executed immediately | **`-y`/`--yes`** flag to skip, but otherwise asks for confirmation before state‑changing operations |
| **SOAP robustness** | Raw `curl` with no error checking | Uses **soap_post()** function with proper XML generation, response inspection, and fault detection |
| **Watch mode** | None | **`watch`** command – automatically restores a NAT mapping if it disappears (continuous monitoring) |
| **MITM** | Only a simple DNS‑hijack with Bettercap | **Separate `mitm` and `dns‑hijack`** – full‑duplex ARP spoofing, stealthy DNS spoofing with domain‑filtering, and auto‑interface detection |
| **Testing** | No safe‑to‑use test command | **`test‑description`** – safely sends a harmless description‑field request to test UPnP input handling **without claiming RCE** |
| **Dependencies** | Required `bettercap`, `upnpc`, `curl` | Same, but now **validates they exist** and gives clear installation hints |
| **Code quality** | Spaghetti code, no functions, no help | **Modular functions**, detailed `--help`, structured with `set -Eeuo pipefail` for maximum robustness |

**Why it matters**:  
The new `hack.sh` is **production‑ready for security labs**. It eliminates guesswork, prevents accidental damage, records everything you do, and lets you automate complex attack chains (e.g., open a backdoor, watch it, then start a MITM in a single scripted session).

---

## ✨ New Features You Should Know

### In `server.py`
- **Threaded server** – handles multiple victims without blocking.
- **Logging to file** – all credentials are saved with timestamps and source IPs.
- **Custom HTML injection** – you can now serve any HTML form, not just the default Facebook clone.
- **Port auto‑detection** – defaults to the machine's primary IP, so you know exactly where to point victims.

### In `hack.sh`
- **Status** – checks if the UPnP endpoint is alive.
- **Discover** – fetches the raw device description XML.
- **Add/Delete** with validation and confirmation.
- **Watch** – keeps a mapping alive – perfect for persistent backdoors.
- **MITM** – full‑duplex ARP spoofing with traffic sniffing (Bettercap).
- **DNS Hijack** – domain‑specific spoofing (e.g., `facebook.com`, `*.google.com`).
- **Test‑Description** – a safe, non‑destructive way to test how the router handles input.

---

## 📦 Installation & Dependencies

### Required Packages (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y python3 curl iproute2 miniupnpc bettercap
```

### For `server.py`
- Python 3.6+ (no external libraries needed – uses only the standard library).

### For `hack.sh`
- Bash 4+, `curl`, `iproute2`, `miniupnpc`, `bettercap`.

---

## 🚀 Usage Quickstart

### Credential Harvester
```bash
# Run on port 8080 (default)
python3 server.py

# Run on port 80 (requires root) with a custom HTML file
sudo python3 server.py -p 80 --html mypage.html

# Log to a custom file
python3 server.py -l my_creds.log
```

### UPnP Lab Script
```bash
# Show status and test the UPnP endpoint
./hack.sh status

# List current NAT mappings
./hack.sh list

# Add a port mapping (external 4444 -> internal 22 on target 192.168.1.7)
./hack.sh add 4444 22 192.168.1.7 TCP -y

# Watch and auto‑restore if removed
./hack.sh watch 4444 22 192.168.1.7 TCP

# Start a full ARP‑MITM against a victim
sudo ./hack.sh mitm 192.168.1.100

# Hijack DNS for facebook.com to your Kali IP
sudo ./hack.sh dns-hijack 192.168.1.100 192.168.1.7 "facebook.com"
```

> **Note**: The new version no longer hardcodes variables – you can override them via environment variables or command‑line options:
> ```bash
> ROUTER=192.168.1.1 ATTACKER=192.168.1.7 ./hack.sh list
> ```

---

## 📁 File Structure

```
.
├── server.py          # Professional credential harvester (new)
├── hack.sh            # Full-featured UPnP & MITM toolkit (new)
├── README.md          # This file
├── credentials.log    # Auto-generated log (when running server.py)
└── upnp_lab.log       # Auto-generated log (when running hack.sh)
```

---

## 📋 Full Command Reference

### `server.py`

| Argument | Description |
|----------|-------------|
| `-H, --host` | Bind address (auto‑detected by default) |
| `-p, --port` | Port to listen on (default: 8080) |
| `-l, --log-file` | File to log captured credentials (default: `credentials.log`) |
| `--html FILE` | Custom HTML file to serve as the login page |

### `hack.sh`

| Command | Description |
|---------|-------------|
| `status` | Show router/local info and test the UPnP endpoint |
| `discover` | Fetch the device description XML |
| `list` | Enumerate current NAT mappings (uses `upnpc`) |
| `add EXT INT TARGET [TCP\|UDP]` | Add a port mapping |
| `delete EXT [TCP\|UDP]` | Remove a port mapping |
| `test-description [EXT]` | Safe input‑handling test (not RCE) |
| `watch EXT INT TARGET [TCP\|UDP]` | Monitor & auto‑restore a mapping |
| `mitm VICTIM` | Start full‑duplex ARP‑MITM with Bettercap |
| `dns-hijack VICTIM [FAKE_IP] [DOMAINS]` | DNS spoofing for specific domains |
| `help` | Show usage |

---

## ⚠️ Safety & Legal Reminder

- **Only run these tools in a lab environment** where you own every device or have explicit written permission.
- The `test-description` command **does not prove command injection** – it simply tests how the router handles input. Always verify execution through other means.
- The `watch` mode automatically restores a mapping – ensure you are authorised before leaving it running.
- The MITM and DNS‑hijack functions are **highly intrusive** – they redirect live traffic. Use with extreme caution.

---

## 🤝 Contributing

If you find a bug or have an enhancement idea, please open an issue or submit a pull request.  
For major changes, please discuss first.

---

## 📄 License

This project is provided for **educational and authorised testing purposes only**.  
The authors assume no liability for misuse. By using this software, you agree to take full responsibility for your actions.

---

**Happy (ethical) hacking!** 🛡️
