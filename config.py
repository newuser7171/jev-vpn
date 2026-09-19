import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).parent.resolve()
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8998"))
DOH_UPSTREAM = os.environ.get("DOH_UPSTREAM", "https://1.1.1.1/dns-query")
CLASSIFIER_ENDPOINT = os.environ.get("CLASSIFIER_ENDPOINT", "https://classifier.dev")
USER_AGENT = "jev-vpn-shield/1.0 (Windows NT; TypeSafe Jev System One)"

# Custom user filter lists
WHITELIST_FILE = BASE_DIR / "whitelist.txt"
CUSTOM_BLOCKLIST_FILE = BASE_DIR / "custom_blocklist.txt"
STATS_FILE = BASE_DIR / "vpn_stats.json"

# Average ad payload size estimate in KB (for bandwidth savings metric)
AVG_AD_PAYLOAD_KB = 150.0
