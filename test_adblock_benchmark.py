import time
import socket
import json
from pathlib import Path
from adblock_engine import AdBlockEngine
from proxy_tunnel import JevVPNTunnel

def run_benchmark():
    print("=" * 60)
    print("🛡️  RUNNING 132-DOMAIN BENCHMARK & ZERO-FALSE-POSITIVE SUITE")
    print("=" * 60)

    engine = AdBlockEngine()
    print(f"Loaded {len(engine.blocked_domains)} blocked domains into AdBlockEngine.")

    # 129 Benchmark domains from Turtlecute33 / d3ward test suite
    benchmark_domains = [
        # Amazon Ads
        "adtago.s3.amazonaws.com", "analyticsengine.s3.amazonaws.com",
        "analytics.s3.amazonaws.com", "advice-ads.s3.amazonaws.com",
        # Google Ads
        "pagead2.googlesyndication.com", "adservice.google.com",
        "pagead2.googleadservices.com", "afs.googlesyndication.com",
        # Doubleclick
        "stats.g.doubleclick.net", "ad.doubleclick.net", "static.doubleclick.net",
        "m.doubleclick.net", "mediavisor.doubleclick.net",
        # Adcolony
        "ads30.adcolony.com", "adc3-launch.adcolony.com", "events3alt.adcolony.com", "wd.adcolony.com",
        # Media.net
        "static.media.net", "media.net", "adservetx.media.net",
        # Google Analytics
        "analytics.google.com", "click.googleanalytics.com", "google-analytics.com", "ssl.google-analytics.com",
        # Hotjar
        "adm.hotjar.com", "identify.hotjar.com", "insights.hotjar.com",
        "script.hotjar.com", "surveys.hotjar.com", "careers.hotjar.com", "events.hotjar.io",
        # MouseFlow
        "mouseflow.com", "cdn.mouseflow.com", "o2.mouseflow.com",
        "gtm.mouseflow.com", "api.mouseflow.com", "tools.mouseflow.com", "cdn-test.mouseflow.com",
        # FreshWorks / Freshmarketer
        "freshmarketer.com", "claritybt.freshmarketer.com", "fwtracks.freshmarketer.com",
        # LuckyOrange
        "luckyorange.com", "api.luckyorange.com", "realtime.luckyorange.com",
        "cdn.luckyorange.com", "w1.luckyorange.com", "upload.luckyorange.net",
        "cs.luckyorange.net", "settings.luckyorange.net",
        # Stats WP Plugin
        "stats.wp.com",
        # Bugsnag
        "notify.bugsnag.com", "sessions.bugsnag.com", "api.bugsnag.com", "app.bugsnag.com",
        # Sentry
        "browser.sentry-cdn.com", "app.getsentry.com",
        # Social Trackers
        "pixel.facebook.com", "an.facebook.com", "static.ads-twitter.com",
        "ads-api.twitter.com", "ads.linkedin.com", "analytics.pointdrive.linkedin.com",
        "ads.pinterest.com", "log.pinterest.com", "trk.pinterest.com",
        "events.reddit.com", "events.redditmedia.com", "ads.youtube.com",
        "ads-api.tiktok.com", "analytics.tiktok.com", "ads-sg.tiktok.com",
        "analytics-sg.tiktok.com", "business-api.tiktok.com", "ads.tiktok.com", "log.byteoversea.com",
        # Mix
        "ads.yahoo.com", "analytics.yahoo.com", "geo.yahoo.com", "udcm.yahoo.com",
        "analytics.query.yahoo.com", "partnerads.ysm.yahoo.com", "log.fc.yahoo.com",
        "gemini.yahoo.com", "adtech.yahooinc.com", "extmaps-api.yandex.net",
        "appmetrica.yandex.ru", "adfstat.yandex.ru", "metrika.yandex.ru",
        "offerwall.yandex.net", "adfox.yandex.ru", "auction.unityads.unity3d.com",
        "webview.unityads.unity3d.com", "config.unityads.unity3d.com", "adserver.unityads.unity3d.com",
        # OEMs
        "iot-eu-logser.realme.com", "iot-logser.realme.com", "bdapi-ads.realmemobile.com", "bdapi-in-ads.realmemobile.com",
        "api.ad.xiaomi.com", "data.mistat.xiaomi.com", "data.mistat.india.xiaomi.com",
        "data.mistat.rus.xiaomi.com", "sdkconfig.ad.xiaomi.com", "sdkconfig.ad.intl.xiaomi.com", "tracking.rus.miui.com",
        "adsfs.oppomobile.com", "adx.ads.oppomobile.com", "ck.ads.oppomobile.com", "data.ads.oppomobile.com",
        "metrics.data.hicloud.com", "metrics2.data.hicloud.com", "grs.hicloud.com",
        "logservice.hicloud.com", "logservice1.hicloud.com", "logbak.hicloud.com",
        "click.oneplus.cn", "open.oneplus.net", "samsungads.com", "smetrics.samsung.com",
        "nmetrics.samsung.com", "samsung-com.112.2o7.net", "analytics-api.samsunghealthcn.com",
        "iadsdk.apple.com", "metrics.icloud.com", "metrics.mzstatic.com",
        "api-adservices.apple.com", "books-analytics-events.apple.com",
        "weather-analytics-events.apple.com", "notes-analytics-events.apple.com"
    ]

    benchmark_domains = sorted(set(benchmark_domains))
    print(f"\n1. Testing {len(benchmark_domains)} benchmark domains against AdBlockEngine...")

    unblocked = []
    for d in benchmark_domains:
        is_b, cat, rule = engine.is_blocked(d, enable_ai=False)
        if not is_b:
            unblocked.append(d)

    blocked_count = len(benchmark_domains) - len(unblocked)
    pct = (blocked_count / len(benchmark_domains)) * 100.0
    print(f"   Score: {blocked_count} / {len(benchmark_domains)} ({pct:.1f}%)")

    assert len(unblocked) == 0, f"Benchmark failures: {unblocked}"
    print("   ✅ 100% of benchmark domains successfully blocked!")

    # 2. Test Legitimate Domains
    print("\n2. Testing legitimate domains to prevent false positives...")
    legit_domains = [
        "google.com", "www.google.com", "maps.google.com", "drive.google.com",
        "github.com", "raw.githubusercontent.com", "api.github.com",
        "microsoft.com", "login.microsoftonline.com", "azure.microsoft.com",
        "apple.com", "support.apple.com", "icloud.com",
        "amazon.com", "aws.amazon.com", "s3.amazonaws.com",
        "wikipedia.org", "en.wikipedia.org",
        "youtube.com", "www.youtube.com",
        "facebook.com", "www.facebook.com",
        "twitter.com", "x.com",
        "reddit.com", "www.reddit.com",
        "linkedin.com", "www.linkedin.com",
        "adblock.turtlecute.org"
    ]

    false_positives = []
    for d in legit_domains:
        is_b, cat, rule = engine.is_blocked(d, enable_ai=False)
        if is_b:
            false_positives.append((d, cat, rule))

    print(f"   Tested {len(legit_domains)} legitimate domains. False positives: {len(false_positives)}")
    assert len(false_positives) == 0, f"False positives detected: {false_positives}"
    print("   ✅ Zero false positives on legitimate websites!")

    # 3. Test Proxy Tunnel Interception (Live Socket Test)
    print("\n3. Testing live proxy CONNECT interception on localhost...")
    test_port = 8891
    tunnel = JevVPNTunnel(port=test_port)
    tunnel.start()
    time.sleep(0.4)

    test_targets = [
        ("adtago.s3.amazonaws.com", True),
        ("adservice.google.com", True),
        ("analytics.google.com", True),
        ("metrics.icloud.com", True),
        ("data.mistat.xiaomi.com", True),
        ("github.com", False)
    ]

    for host, should_block in test_targets:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", tunnel.port))
        req = f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode("latin1")
        s.sendall(req)
        resp = s.recv(1024).decode("latin1", errors="ignore")
        s.close()

        if should_block:
            assert "403 Blocked" in resp, f"Expected 403 Blocked for {host}, got: {resp}"
            print(f"   [PROXY BLOCK] {host:32} -> 403 Forbidden (Blocked)")
        else:
            assert "200 Connection Established" in resp, f"Expected 200 for {host}, got: {resp}"
            print(f"   [PROXY PASS]  {host:32} -> 200 OK (Allowed)")

    tunnel.stop()
    print("   ✅ Live proxy tunnel interception tests passed cleanly!")

    print("\n" + "=" * 60)
    print("🎉 ALL BENCHMARK & PRIVACY TESTS PASSED (100% BLOCK RATE)")
    print("=" * 60)

if __name__ == "__main__":
    run_benchmark()
