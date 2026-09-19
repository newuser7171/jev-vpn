import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from config import CLASSIFIER_ENDPOINT, USER_AGENT

def classify_domains_batch(
    domains: List[str],
    tier: str = "fast"
) -> List[Dict[str, Any]]:
    """
    Classifies a batch of domains against advertising and tracking categories
    using classifier.dev (Jev System One).
    Supports up to 1,000 domains in 1 HTTP call.
    """
    if not domains:
        return []

    labels = [
        "advertisement_banner",
        "behavioral_tracker",
        "telemetry_analytics",
        "clean_content_cdn",
        "malware_malvertising",
        "none of these"
    ]
    instructions = (
        "Classify domains by their primary purpose. Flag advertising networks, ad exchanges, "
        "and popunder scripts as advertisement_banner. Flag analytics beacons and user tracking as behavioral_tracker "
        "or telemetry_analytics. Legitimate user websites, APIs, and CDN assets are clean_content_cdn."
    )

    chunk_size = 1000
    all_results = []

    # Use direct opener with no proxy to avoid local proxy feedback loop
    direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    for i in range(0, len(domains), chunk_size):
        chunk = domains[i:i + chunk_size]
        payload = {
            "inputs": chunk,
            "labels": labels,
            "instructions": instructions,
            "tier": tier
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            CLASSIFIER_ENDPOINT,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT
            }
        )

        try:
            with direct_opener.open(req, timeout=7.0) as resp:
                data = json.load(resp)
                raw_results = data.get("results", [])
                for dom, res in zip(chunk, raw_results):
                    verdict = res.get("label", "clean_content_cdn")
                    if verdict == "none of these":
                        verdict = "clean_content_cdn"
                    raw_conf = res.get("confidence")
                    conf = float(raw_conf) if raw_conf is not None else 0.0
                    is_ad = verdict in [
                        "advertisement_banner",
                        "behavioral_tracker",
                        "telemetry_analytics",
                        "malware_malvertising"
                    ]
                    all_results.append({
                        "domain": dom,
                        "verdict": verdict,
                        "confidence": conf,
                        "is_ad": is_ad,
                        "model": res.get("model", "jev-fast")
                    })
        except Exception as e:
            for dom in chunk:
                all_results.append({
                    "domain": dom,
                    "verdict": "unknown",
                    "confidence": 0.0,
                    "is_ad": False,
                    "error": str(e)
                })

    return all_results

def classify_single_domain(domain: str) -> Dict[str, Any]:
    res = classify_domains_batch([domain])
    return res[0] if res else {"domain": domain, "verdict": "clean_content_cdn", "confidence": 0.0, "is_ad": False}
