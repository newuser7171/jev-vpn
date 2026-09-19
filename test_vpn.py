import time
import socket
import urllib.request
from adblock_engine import AdBlockEngine
from classifier_bridge import classify_domains_batch
from proxy_tunnel import JevVPNTunnel
from system_proxy import is_proxy_enabled

def test_adblock_engine():
    print("=== 1. TESTING ADBLOCK ENGINE ===")
    engine = AdBlockEngine()

    ads = [
        "pagead2.googlesyndication.com",
        "adservice.google.com",
        "securepubads.g.doubleclick.net",
        "static.criteo.net",
        "pixel.facebook.com",
        "telemetry.microsoft.com",
        "adskeeper.co.uk"
    ]
    for ad in ads:
        is_blocked, cat, rule = engine.is_blocked(ad, enable_ai=False)
        print(f"  Ad: '{ad}' -> Blocked={is_blocked} | Category={cat} | Rule={rule}")
        assert is_blocked, f"Failed to block ad domain {ad}"

    clean = [
        "github.com",
        "google.com",
        "en.wikipedia.org",
        "microsoft.com",
        "stackoverflow.com"
    ]
    for c in clean:
        is_blocked, cat, rule = engine.is_blocked(c, enable_ai=False)
        print(f"  Clean: '{c}' -> Blocked={is_blocked} | Category={cat}")
        assert not is_blocked, f"False positive on clean domain {c}"

    print("  ✅ AdBlock Engine passed cleanly.")

def test_ai_classifier_bridge():
    print("\n=== 2. TESTING CLASSIFIER.DEV AD TRIAGE ===")
    domains = [
        "github.com",
        "adnxs-mobile-exchange.net",
        "user-telemetry-beacon.xyz"
    ]
    res = classify_domains_batch(domains)
    print(f"  Classified {len(res)} domains in 1 HTTP call:")
    for r in res:
        print(f"    Domain: '{r['domain']}' -> Verdict: {r['verdict']}, Conf: {r['confidence']:.2f}, IsAd: {r['is_ad']}")
    
    assert not res[0]["is_ad"], "False positive on github.com"
    assert res[1]["is_ad"], "Failed to identify ad network"
    print("  ✅ Classifier bridge passed cleanly.")

def test_proxy_tunnel_interception():
    print("\n=== 3. TESTING LOCAL PROXY TUNNEL INTERCEPTION ===")
    test_port = 8899
    tunnel = JevVPNTunnel(port=test_port)
    tunnel.start()
    time.sleep(0.5)

    # Configure opener to route through test proxy
    proxy_handler = urllib.request.ProxyHandler({
        'http': f'http://127.0.0.1:{test_port}',
        'https': f'http://127.0.0.1:{test_port}'
    })
    opener = urllib.request.build_opener(proxy_handler)

    # 1. Request to an Ad URL -> should be sinkholed with 204 No Content
    print("  Testing HTTP GET to ad domain via proxy tunnel...")
    req_ad = urllib.request.Request(
        "http://adservice.google.com/ads.js",
        headers={"User-Agent": "test-client/1.0"}
    )
    with opener.open(req_ad) as resp:
        print(f"  Ad Response Status: {resp.status} (Expected 204 No Content)")
        assert resp.status == 204, f"Unexpected response status: {resp.status}"

    stats = tunnel.stats.get_summary()
    print(f"  Tunnel Stats: Total={stats['total_requests']}, AdsBlocked={stats['ads_blocked']}, Trackers={stats['trackers_blocked']}, Saved={stats['saved_mb']}MB")
    assert (stats["ads_blocked"] + stats["trackers_blocked"]) >= 1, "Ad block not recorded in stats"

    tunnel.stop()
    print("  ✅ Proxy tunnel interception passed cleanly.")

def test_system_proxy_state():
    print("\n=== 4. TESTING SYSTEM PROXY STATE INSPECTION ===")
    enabled, srv = is_proxy_enabled()
    print(f"  Current Windows Proxy State: Enabled={enabled}, Server='{srv}'")
    print("  ✅ System proxy check passed cleanly.")

if __name__ == "__main__":
    test_adblock_engine()
    test_ai_classifier_bridge()
    test_proxy_tunnel_interception()
    test_system_proxy_state()
    print("\n🎉 ALL JEV-VPN & ADSHIELD TESTS PASSED SUCCESSFULLY!")
