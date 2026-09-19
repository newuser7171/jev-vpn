from pathlib import Path
from typing import Tuple, Set, Dict, Any, Optional
from config import WHITELIST_FILE, CUSTOM_BLOCKLIST_FILE
from classifier_bridge import classify_single_domain

# Comprehensive core ad & tracking networks
CORE_AD_DOMAINS = {
    # Google Ad Ecosystem
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "adservice.google.com", "pagead2.googlesyndication.com", "partner.googleadservices.com",
    "admob.com", "google-analytics.com", "analytics.google.com",

    # Major Ad Exchanges & Networks
    "adnxs.com", "ib.adnxs.com", "criteo.com", "static.criteo.net",
    "taboola.com", "outbrain.com", "rubiconproject.com", "pubmatic.com",
    "openx.net", "casalemedia.com", "adroll.com", "smartadserver.com",
    "amazon-adsystem.com", "advertising.com", "media.net", "adtechus.com",
    "serving-sys.com", "adcolony.com", "unityads.unity3d.com", "vungle.com",
    "chartboost.com", "inmobi.com", "applovin.com", "ironsrc.com",

    # Trackers, Analytics & Fingerprinting
    "quantserve.com", "scorecardresearch.com", "hotjar.com", "mouseflow.com",
    "crazyegg.com", "inspectlet.com", "mixpanel.com", "amplitude.com",
    "segment.io", "segment.com", "branch.io", "appsflyer.com", "adjust.com",
    "kochava.com", "singular.net", "optimizely.com",

    # Social & Big Tech Telemetry / Tracking Beacons
    "pixel.facebook.com", "an.facebook.com", "graph.instagram.com",
    "analytics.tiktok.com", "ads.twitter.com", "ads.pinterest.com",
    "telemetry.microsoft.com", "vortex.data.microsoft.com", "watson.telemetry.microsoft.com",
    "telemetry.spotify.com", "spclient.wg.spotify.com/ads"
}

AD_KEYWORDS = [
    "adservice", "doubleclick", "adserver", "adskeeper", "adsystem",
    "adnxs", "popads", "popcash", "propellerads", "zeroredirect"
]

class AdBlockEngine:
    """
    High-performance in-memory domain filter combining static blocklists,
    subdomain tree matching, user whitelist/blacklist, and AI zero-day triage.
    """
    def __init__(self):
        self.core_blocks: Set[str] = set(CORE_AD_DOMAINS)
        self.whitelist: Set[str] = self._load_set(WHITELIST_FILE)
        self.custom_blocks: Set[str] = self._load_set(CUSTOM_BLOCKLIST_FILE)
        self._ai_cache: Dict[str, Tuple[bool, str]] = {}

    def _load_set(self, filepath: Path) -> Set[str]:
        s = set()
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            s.add(line)
            except Exception:
                pass
        return s

    def add_to_whitelist(self, domain: str):
        self.whitelist.add(domain.lower().strip())
        self._save_set(WHITELIST_FILE, self.whitelist)

    def add_to_custom_blocks(self, domain: str):
        self.custom_blocks.add(domain.lower().strip())
        self._save_set(CUSTOM_BLOCKLIST_FILE, self.custom_blocks)

    def _save_set(self, filepath: Path, data: Set[str]):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                for item in sorted(data):
                    f.write(item + "\n")
        except Exception:
            pass

    def is_blocked(self, raw_host: str, enable_ai: bool = True) -> Tuple[bool, str, str]:
        """
        Determines if a hostname or domain should be blocked.
        Returns: (is_blocked: bool, category: str, matched_rule: str)
        """
        # Strip port if present
        host = raw_host.split(":")[0].strip().lower()
        if not host:
            return False, "Clean", ""

        # 1. Whitelist check (highest priority)
        if host in self.whitelist:
            return False, "Whitelisted", host

        # 2. Custom blocklist check
        if host in self.custom_blocks:
            return True, "User Blocklist", host

        # 3. Core blocklist check (exact and suffix matching)
        parts = host.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.core_blocks:
                return True, "Ad/Tracker Network", parent

        # 4. Keyword heuristic check
        for kw in AD_KEYWORDS:
            if kw in host:
                return True, "Heuristic Ad Pattern", kw

        # 5. AI Zero-Day Classifier check (for ambiguous or suspicious subdomains)
        if enable_ai and ("ads." in host or "track." in host or "telemetry." in host or "pixel." in host):
            if host in self._ai_cache:
                is_b, cat = self._ai_cache[host]
                return is_b, cat, "AI Cache"

            ai_res = classify_single_domain(host)
            if ai_res.get("is_ad"):
                cat = f"AI {ai_res['verdict']} ({ai_res['confidence']:.2f})"
                self._ai_cache[host] = (True, cat)
                return True, cat, "Jev System One"
            else:
                self._ai_cache[host] = (False, "Clean")

        return False, "Clean Content", ""
