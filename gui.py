import sys
import time
import json
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any

import customtkinter as ctk
from tkinter import messagebox

from config import PROXY_HOST, PROXY_PORT, STATS_FILE
from proxy_tunnel import JevVPNTunnel
from adblock_engine import AdBlockEngine
from system_proxy import enable_system_proxy, disable_system_proxy, is_proxy_enabled

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class JevVPNGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Jev-VPN: Autonomous AI Privacy Tunnel & Smart Ad/Tracker Shield")
        self.geometry("1100x780")
        self.minsize(950, 680)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.tunnel = JevVPNTunnel(host=PROXY_HOST, port=PROXY_PORT)
        self.adblock = AdBlockEngine()
        self.is_connected = False
        self.tunnel.set_on_block_callback(self._on_ad_blocked)

        self._build_ui()
        self._check_initial_proxy_status()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # -------------------------------------------------------------
        # 1. Header Bar
        # -------------------------------------------------------------
        hdr = ctk.CTkFrame(self, fg_color="#0a0e17", corner_radius=0, height=80)
        hdr.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        hdr.grid_columnconfigure(1, weight=1)

        logo = ctk.CTkLabel(
            hdr, text="🛡️ JEV-VPN & ADSHIELD",
            font=ctk.CTkFont(size=22, weight="bold"), text_color="#00d2ff"
        )
        logo.grid(row=0, column=0, padx=25, pady=(15, 2), sticky="w")

        sub = ctk.CTkLabel(
            hdr, text="Autonomous Encrypted Privacy Tunnel & Zero-Day Ad/Tracker Neutralizer",
            font=ctk.CTkFont(size=12), text_color="#8b949e"
        )
        sub.grid(row=1, column=0, padx=25, pady=(0, 15), sticky="w")

        self.status_badge = ctk.CTkLabel(
            hdr, text="● DISCONNECTED",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f85149",
            fg_color="#21262d",
            corner_radius=12,
            padx=15, pady=6
        )
        self.status_badge.grid(row=0, column=2, rowspan=2, padx=25, pady=20, sticky="e")

        # -------------------------------------------------------------
        # 2. Main Control & Connect Card
        # -------------------------------------------------------------
        ctrl_card = ctk.CTkFrame(self, fg_color="#161b22", corner_radius=12)
        ctrl_card.grid(row=1, column=0, sticky="ew", padx=20, pady=(15, 10))
        ctrl_card.grid_columnconfigure((0, 1), weight=1)

        self.btn_connect = ctk.CTkButton(
            ctrl_card,
            text="🛡️ CONNECT VPN & ADSHIELD",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=50,
            fg_color="#238636",
            hover_color="#2ea043",
            command=self._toggle_vpn
        )
        self.btn_connect.grid(row=0, column=0, padx=(25, 10), pady=(18, 10), sticky="ew")

        self.btn_browser = ctk.CTkButton(
            ctrl_card,
            text="🌐 OPEN PROTECTED BROWSER",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=50,
            fg_color="#1f6feb",
            hover_color="#388bfd",
            command=self._open_protected_browser
        )
        self.btn_browser.grid(row=0, column=1, padx=(10, 25), pady=(18, 10), sticky="ew")

        self.check_sys_proxy = ctk.CTkCheckBox(
            ctrl_card,
            text="Enforce Windows System Proxy (all apps, Chrome, Edge, Spotify routed via tunnel)",
            font=ctk.CTkFont(size=12),
            text_color="#c9d1d9"
        )
        self.check_sys_proxy.select()
        self.check_sys_proxy.grid(row=1, column=0, columnspan=2, padx=25, pady=(0, 14), sticky="w")

        # -------------------------------------------------------------
        # 3. 4 Stat Cards
        # -------------------------------------------------------------
        stat_frame = ctk.CTkFrame(self, fg_color="transparent")
        stat_frame.grid(row=2, column=0, sticky="ew", padx=15, pady=(5, 10))
        stat_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_ads = self._create_card(stat_frame, 0, "ADS BLOCKED", "0", "#ff7b72")
        self.card_trackers = self._create_card(stat_frame, 1, "TRACKERS STOPPED", "0", "#d29922")
        self.card_saved = self._create_card(stat_frame, 2, "EST. BANDWIDTH SAVED", "0 MB", "#3fb950")
        self.card_total = self._create_card(stat_frame, 3, "TOTAL REQUESTS", "0", "#58a6ff")

        # -------------------------------------------------------------
        # 4. Live Stream & Domain Tester Frame
        # -------------------------------------------------------------
        bottom_frame = ctk.CTkFrame(self, fg_color="#161b22", corner_radius=12)
        bottom_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=(5, 15))
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_rowconfigure(2, weight=1)

        # Quick Test Bar
        test_bar = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        test_bar.grid(row=0, column=0, sticky="ew", padx=15, pady=(12, 8))

        self.test_input = ctk.CTkEntry(
            test_bar,
            placeholder_text="Test any domain (e.g. adservice.google.com, doubleclick.net, github.com)...",
            height=36,
            font=ctk.CTkFont(size=12)
        )
        self.test_input.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_test = ctk.CTkButton(
            test_bar, text="⚡ Test Domain", height=36, width=120,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._test_domain
        )
        btn_test.pack(side="right")

        lbl_log = ctk.CTkLabel(
            bottom_frame, text="Real-Time Neutralized Ads & Trackers Stream",
            font=ctk.CTkFont(size=13, weight="bold"), text_color="#c9d1d9"
        )
        lbl_log.grid(row=1, column=0, padx=15, sticky="w", pady=(5, 2))

        self.feed_box = ctk.CTkTextbox(
            bottom_frame,
            fg_color="#0a0e17",
            text_color="#ff7b72",
            font=ctk.CTkFont(family="Consolas", size=11)
        )
        self.feed_box.grid(row=2, column=0, sticky="nsew", padx=15, pady=(0, 15))

    def _create_card(self, parent, col, title, val, color):
        card = ctk.CTkFrame(parent, fg_color="#161b22", corner_radius=10)
        card.grid(row=0, column=col, padx=5, pady=5, sticky="ew")
        t = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color="#8b949e")
        t.pack(anchor="w", padx=15, pady=(10, 0))
        v = ctk.CTkLabel(card, text=val, font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
        v.pack(anchor="w", padx=15, pady=(2, 10))
        return v

    def _check_initial_proxy_status(self):
        active, srv = is_proxy_enabled()
        if active and ":" in srv:
            try:
                srv_port = int(srv.split(":")[-1])
                self.tunnel.port = srv_port
                self.tunnel.start()
                self.is_connected = True
                self._set_connected_state()
                self._start_stats_updater()
            except Exception:
                pass

    def _toggle_vpn(self):
        if not self.is_connected:
            try:
                # Start Tunnel (auto-falls back if port 8998 or 8080 is busy)
                self.tunnel.start()
                actual_port = self.tunnel.port

                if self.check_sys_proxy.get():
                    ok, msg = enable_system_proxy(port=actual_port)
                    if not ok:
                        messagebox.showwarning("Proxy Warning", f"Could not set system proxy:\n{msg}")

                self.is_connected = True
                self._set_connected_state()
                self._start_stats_updater()
            except Exception as e:
                messagebox.showerror("VPN Error", f"Failed to start Jev-VPN Tunnel:\n{e}")
        else:
            # Stop Tunnel
            self.tunnel.stop()
            disable_system_proxy()
            self.is_connected = False
            self._set_disconnected_state()

    def _open_protected_browser(self):
        """
        Launches Google Chrome (or Microsoft Edge) explicitly configured to route 100%
        of traffic through the Jev-VPN tunnel. Bypasses any cached sockets or QUIC UDP.
        """
        if not self.is_connected:
            self._toggle_vpn()

        port = self.tunnel.port
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        ]

        target_url = "https://adblock.turtlecute.org/"
        for exe in candidates:
            if Path(exe).exists():
                cmd = [exe, f"--proxy-server=http://127.0.0.1:{port}", target_url]
                try:
                    subprocess.Popen(cmd)
                    self.feed_box.insert("end", f"[{time.strftime('%H:%M:%S')}] 🌐 Launched Protected Browser ({Path(exe).name}) routed through 127.0.0.1:{port}\n")
                    self.feed_box.see("end")
                    return
                except Exception as e:
                    messagebox.showerror("Launch Error", f"Failed to launch browser:\n{e}")
                    return

        messagebox.showinfo("Browser Info", f"Jev-VPN is active on 127.0.0.1:{port}.\nPlease open Chrome and navigate to {target_url}")

    def _set_connected_state(self):
        port = self.tunnel.port
        self.btn_connect.configure(text="⏹ DISCONNECT VPN & ADSHIELD", fg_color="#da3633", hover_color="#f85149")
        self.status_badge.configure(text=f"● PROTECTED ({port})", text_color="#3fb950")
        self.feed_box.insert("end", f"[{time.strftime('%H:%M:%S')}] 🛡️ Jev-VPN Privacy Tunnel Connected. Local proxy active on 127.0.0.1:{port}.\n")
        self.feed_box.see("end")

    def _set_disconnected_state(self):
        self.btn_connect.configure(text="🛡️ CONNECT VPN & ADSHIELD", fg_color="#238636", hover_color="#2ea043")
        self.status_badge.configure(text="● DISCONNECTED", text_color="#f85149")
        self.feed_box.insert("end", f"[{time.strftime('%H:%M:%S')}] ⏹ Tunnel disconnected. Direct internet connection restored.\n")
        self.feed_box.see("end")

    def _on_ad_blocked(self, ev: Dict[str, Any]):
        def update():
            try:
                line = f"[{ev['time']}] 🚫 BLOCKED: {ev['domain']:<32} | {ev['category']} ({ev['rule']})\n"
                self.feed_box.insert("end", line)
                self.feed_box.see("end")
            except Exception:
                pass
        self.after(0, update)

    def _start_stats_updater(self):
        def loop():
            while self.is_connected:
                st = self.tunnel.stats.get_summary()
                self.card_ads.configure(text=str(st["ads_blocked"]))
                self.card_trackers.configure(text=str(st["trackers_blocked"]))
                self.card_saved.configure(text=f"{st['saved_mb']} MB")
                self.card_total.configure(text=str(st["total_requests"]))
                
                # Persist to disk
                try:
                    with open(STATS_FILE, "w", encoding="utf-8") as f:
                        json.dump(st, f, indent=2)
                except Exception:
                    pass

                time.sleep(1.5)

        threading.Thread(target=loop, daemon=True).start()

    def _test_domain(self):
        dom = self.test_input.get().strip()
        if not dom:
            return
        
        is_blocked, cat, rule = self.adblock.is_blocked(dom, enable_ai=True)
        status = "🚫 BLOCKED" if is_blocked else "✅ ALLOWED"
        
        self.feed_box.insert("end", f"\n[DOMAIN TEST] {dom} -> {status} [{cat}] (Rule: {rule})\n")
        self.feed_box.see("end")

    def _on_close(self):
        if self.is_connected:
            self.tunnel.stop()
            disable_system_proxy()
        self.destroy()

def launch_gui():
    app = JevVPNGUI()
    app.mainloop()

if __name__ == "__main__":
    launch_gui()
