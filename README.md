# UPnP Pentesting Toolkit (Realtek / D-Link DSL-124)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kali](https://img.shields.io/badge/OS-Kali_Linux-blue)](https://www.kali.org/)
[![Bash](https://img.shields.io/badge/Shell-Bash-green)](https://www.gnu.org/software/bash/)

**A minimal, yet complete, toolkit to exploit unauthenticated UPnP vulnerabilities on Realtek-based routers (e.g., D-Link DSL-124).**

This toolkit demonstrates how an attacker on a local network can take full control of a router's firewall (NAT table), bypass UDP forwarding limitations, and perform a stealthy man-in-the-middle (MITM) attack to harvest credentials.

---

## 📡 Vulnerability Deep Dive

### The Target
- **Hardware:** D-Link DSL-124 (and other Realtek SDK routers).
- **Firmware:** ME_1.00 / BLR-TX4S.
- **Service:** MiniUPnP running on TCP port `5431`.

### The Flaw (Unauthenticated SOAP)
The router runs a SOAP server at `/control/WANIPConnection`. This service allows any device on the Local Area Network (LAN) to call functions like `AddPortMapping` (opening ports) or `DeletePortMapping` (closing ports).

**The critical issue:** The SOAP server does **not** require authentication. No username, no password, no token. Any client that can reach `192.168.1.1:5431` can modify the firewall.

---

## 🔄 Attack Chain Explanation

This toolkit executes a 4-phase attack to establish persistence, bypass network restrictions, and harvest data.

### Phase 1: TCP Backdoor (Firewall Control)
- **Action:** Sends a crafted SOAP envelope to `AddPortMapping`.
- **Result:** Opens a permanent TCP port (`4444`) on the router, forwarding all incoming traffic directly to the attacker's SSH (port `22`).
- **Why it matters:** This is a persistent backdoor. Even if the WiFi password changes, the port forward remains active.

### Phase 2: DNS Hijack (MITM Setup)
- **Action:** Uses `bettercap` to perform ARP Spoofing. 
- **Result:** The victim's machine is tricked into thinking the Attacker's IP is the Router. All their traffic physically passes through the Attacker.
- **Why it matters:** This bypasses the need to forward UDP ports (like DNS port 53), which the router silently blocks. We don't ask the router for permission; we just intercept the traffic directly.

### Phase 3: Domain Spoofing
- **Action:** Intercepts the victim's DNS requests.
- **Result:** When the victim asks for `facebook.com`, the attacker replies with their own IP address instead of the real one.
- **Why it matters:** The victim's browser is now unknowingly directed to the Attacker's machine when they try to visit Facebook.

### Phase 4: Credential Harvesting
- **Action:** Serves a clone of the Facebook login page via a Python HTTP server.
- **Result:** When the victim enters their username and password and hits "Log In", the data is POSTed to the Attacker's server.
- **The Payoff:** Credentials are printed in plaintext to the Attacker's terminal. The victim is then redirected to the real Facebook, completely unaware of the interception.

---

## ⚙️ Prerequisites

- **Kali Linux** (Recommended)
- Tools pre-installed: `curl`, `upnpc` (miniupnpc), `bettercap`, `python3`
- **Target Environment:** Local Area Network access.

---

## 🚀 Quick Start Guide

### 1. Clone & Configure
```bash
git clone https://github.com/rick-sovior/UPnP-Toolkit.git
cd UPnP-Toolkit
chmod +x hack.sh
