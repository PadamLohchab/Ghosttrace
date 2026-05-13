"""
GhostTrace — Threat Intelligence
Checks IOCs against free threat intel APIs.

Supported (all free tiers):
  - ip-api.com    (IP reputation, no key)
  - AbuseIPDB     (requires free API key: ABUSEIPDB_API_KEY in .env)
  - VirusTotal    (requires free API key: VIRUSTOTAL_API_KEY in .env)
"""

import os
import requests
from utils.logger import get_logger

log = get_logger("threat_intel")

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


# ── IP Reputation ─────────────────────────────────────────────────────────────

def check_ip_abuseipdb(ip: str) -> dict:
    """
    Check IP against AbuseIPDB.
    Returns: {abuse_score, country, usage_type, isp, is_tor, reports}
    Requires ABUSEIPDB_API_KEY in .env
    """
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set in .env"}

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "ip":           ip,
            "abuse_score":  data.get("abuseConfidenceScore", 0),
            "country":      data.get("countryCode", "Unknown"),
            "usage_type":   data.get("usageType", "Unknown"),
            "isp":          data.get("isp", "Unknown"),
            "is_tor":       data.get("isTor", False),
            "total_reports":data.get("totalReports", 0),
            "source":       "AbuseIPDB",
        }
    except Exception as e:
        log.warning(f"[ThreatIntel] AbuseIPDB lookup failed for {ip}: {e}")
        return {"error": str(e)}


def check_hash_virustotal(file_hash: str) -> dict:
    """
    Check a file hash (MD5/SHA1/SHA256) against VirusTotal.
    Returns: {malicious, suspicious, harmless, undetected, permalink}
    Requires VIRUSTOTAL_API_KEY in .env
    """
    if not VIRUSTOTAL_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            return {"hash": file_hash, "status": "not_found", "source": "VirusTotal"}
        r.raise_for_status()
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "hash":        file_hash,
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "permalink":   f"https://www.virustotal.com/gui/file/{file_hash}",
            "source":      "VirusTotal",
        }
    except Exception as e:
        log.warning(f"[ThreatIntel] VirusTotal lookup failed for {file_hash}: {e}")
        return {"error": str(e)}


def check_domain_virustotal(domain: str) -> dict:
    """
    Check a domain against VirusTotal.
    Requires VIRUSTOTAL_API_KEY in .env
    """
    if not VIRUSTOTAL_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "domain":     domain,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "permalink":  f"https://www.virustotal.com/gui/domain/{domain}",
            "source":     "VirusTotal",
        }
    except Exception as e:
        log.warning(f"[ThreatIntel] VirusTotal domain lookup failed for {domain}: {e}")
        return {"error": str(e)}


def bulk_check_iocs(iocs: list) -> list:
    """
    Run threat intel checks on a list of IOC dicts.
    Each IOC dict should have 'type' and 'value' keys.
    Returns the list with added 'threat_intel' field.
    """
    results = []
    for ioc in iocs:
        ioc_type  = ioc.get("type", "").upper()
        ioc_value = ioc.get("value", "")
        intel     = {}

        if ioc_type == "IP" and ABUSEIPDB_KEY:
            intel = check_ip_abuseipdb(ioc_value)
        elif ioc_type in ("HASH", "MD5", "SHA256", "SHA1") and VIRUSTOTAL_KEY:
            intel = check_hash_virustotal(ioc_value)
        elif ioc_type == "DOMAIN" and VIRUSTOTAL_KEY:
            intel = check_domain_virustotal(ioc_value)

        enriched = dict(ioc)
        enriched["threat_intel"] = intel
        results.append(enriched)

    return results
