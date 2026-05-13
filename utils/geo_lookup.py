"""
GhostTrace — IP Geolocation
Uses ip-api.com (free, no key, 45 req/min limit).
Falls back gracefully on network errors.
"""

import re
import requests
from utils.logger import get_logger

log = get_logger("geo_lookup")

# IPs to never look up
_PRIVATE_PREFIXES = ("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "0.", "255.")

SUSPICIOUS_ORGS = [
    "tor", "vpn", "proxy", "hosting", "datacenter", "cloud",
    "digitalocean", "hetzner", "linode", "vultr", "aws", "azure",
    "ovh", "choopa", "psychz", "multacom",
]


def is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES)


def is_suspicious(data: dict) -> bool:
    """Heuristic: datacenter / hosting / VPN / Tor = suspicious."""
    combined = (data.get("org", "") + " " + data.get("isp", "")).lower()
    return any(s in combined for s in SUSPICIOUS_ORGS)


def lookup_ip(ip: str) -> dict:
    """
    Look up a single IP address.
    Returns a dict with: ip, country, country_code, city, isp, org, severity
    """
    if is_private(ip):
        return {
            "ip": ip, "country": "Private", "country_code": "LO",
            "city": "LAN", "isp": "Private Network", "org": "",
            "severity": "LOW",
        }

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}"
            f"?fields=status,country,countryCode,city,isp,org,as,query",
            timeout=5,
        )
        data = r.json()
        if data.get("status") == "success":
            sev = "HIGH" if is_suspicious(data) else "MEDIUM"
            return {
                "ip":           ip,
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "UN"),
                "city":         data.get("city", "Unknown"),
                "isp":          data.get("isp", "Unknown"),
                "org":          data.get("org", "Unknown"),
                "as":           data.get("as", "Unknown"),
                "severity":     sev,
            }
    except Exception as e:
        log.warning(f"[GeoLookup] Failed for {ip}: {e}")

    return {
        "ip": ip, "country": "Unknown", "country_code": "UN",
        "city": "Unknown", "isp": "Unknown", "org": "Unknown",
        "as": "Unknown", "severity": "MEDIUM",
    }


def extract_public_ips(text: str) -> list:
    """Extract all non-private IPs from a block of text."""
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    found   = re.findall(pattern, text)
    return [ip for ip in set(found) if not is_private(ip)]


def lookup_bulk(ips: list, max_ips: int = 15) -> list:
    """Look up a list of IPs, limited to max_ips to respect rate limits."""
    results = []
    for ip in list(set(ips))[:max_ips]:
        info = lookup_ip(ip)
        results.append(info)
        log.info(f"[GeoLookup] {ip} → {info.get('country')} ({info.get('severity')})")
    return results
