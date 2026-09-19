# 🛡️ Jev-VPN: Autonomous AI Privacy Tunnel & Smart Ad/Tracker Shield

A lightweight, zero-configuration **privacy tunnel (VPN/Proxy)** and **intelligent Ad & Tracker Shield** for Windows. Jev-VPN intercepts network-level advertising requests, behavioral tracking beacons, invasive telemetry, and malvertising before they load in browsers (Edge, Chrome, Firefox) or desktop applications (Spotify, Discord, etc.).

Powered by **TypeSafe's Jev System One** and **`classifier.dev`**, Jev-VPN pairs static blocklists (EasyList, AdGuard, StevenBlack) with a live **AI Zero-Day Ad Classifier** that semantically identifies dynamic, obfuscated ad delivery networks that static lists miss.

---

## ⚡ Core Capabilities

* 🛡️ **Network-Level Ad & Tracker Neutralizer** ([`adblock_engine.py`](file:///C:/Users/newuser/.gemini/antigravity/scratch/jev-vpn/adblock_engine.py)):
  * Blocks Google AdServices, DoubleClick, Taboola, Outbrain, Criteo, AppNexus, Facebook Pixel, and tracking telemetry at the socket layer.
  * Responds to ad requests with instant `HTTP 204 No Content` so page containers collapse seamlessly without broken image placeholders or console errors.
* 🧠 **AI Zero-Day Ad Triage** ([`classifier_bridge.py`](file:///C:/Users/newuser/.gemini/antigravity/scratch/jev-vpn/classifier_bridge.py)):
  * Leverages **`classifier.dev`** (Jev System One) to classify unknown domains against `advertisement_banner`, `behavioral_tracker`, `telemetry_analytics`, and `malware_malvertising`.
* 🔒 **Encrypted Privacy Tunnel & DoH** ([`proxy_tunnel.py`](file:///C:/Users/newuser/.gemini/antigravity/scratch/jev-vpn/proxy_tunnel.py)):
  * Multi-threaded HTTP CONNECT proxy engine running locally on `127.0.0.1:8080`.
  * Protects and splices TLS traffic without inspecting private payload contents.
* 🔄 **1-Click Windows System Proxy Integration** ([`system_proxy.py`](file:///C:/Users/newuser/.gemini/antigravity/scratch/jev-vpn/system_proxy.py)):
  * Seamlessly toggles the Windows system proxy (`WinINet`) so all Windows apps and browsers instantly route through Jev-VPN.
  * Auto-disables on exit to ensure you never lose direct internet connectivity.
* 📊 **Live Bandwidth & Tracker Metrics**:
  * Tracks total requests, ads blocked count, trackers neutralized count, and calculates estimated bandwidth saved (MB/GB).

---

## 🖥️ Cyber Desktop GUI

Launch the graphical dashboard with any of the following:

```bash
# Via Python:
python gui.py

# Via CLI:
python cli.py gui

# Or double-click:
jev-vpn-gui.bat
```

### GUI Features
1. **Big Power Button**: 1-click toggle to connect/disconnect the encrypted tunnel and ad shield.
2. **System Proxy Switch**: Toggle automatic system-wide routing for Edge, Chrome, Spotify, etc.
3. **4 Live Metric Cards**: Real-time counter of Ads Blocked, Trackers Stopped, Est. Bandwidth Saved, and Total Requests.
4. **Quick Domain Tester**: Interactive bar to test any domain instantly against the filter engine.
5. **Real-Time Blocked Stream**: Scrolling visual log showing blocked ads as you browse the web.

---

## ⌨️ CLI Usage

```bash
# 1. Start VPN & AdShield proxy tunnel (with auto Windows proxy):
python cli.py start

# 2. Start proxy only (no Windows system proxy modification):
python cli.py start --no-system-proxy --port 8080

# 3. Test whether a domain is recognized as an ad/tracker:
python cli.py test adservice.google.com
python cli.py test github.com

# 4. Check or toggle Windows system proxy manually:
python cli.py system-proxy status
python cli.py system-proxy on
python cli.py system-proxy off

# 5. Add custom domain to whitelist:
python cli.py whitelist my-allowed-domain.com

# 6. Add custom domain to blocklist:
python cli.py blocklist unwanted-tracking-site.com
```

---

## 🧪 Verification & Test Suite

Run the automated test suite verifying all 4 components:

```bash
python test_vpn.py
```
