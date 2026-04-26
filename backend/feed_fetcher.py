"""
feed_fetcher.py — Threat Intel Feed Fetcher

Run via cron every 6 hours:
  0 */6 * * * cd /path/to/backend && python feed_fetcher.py

Fetches from 5 free APIs (no API keys needed):
- CISA KEV
- ThreatFox (abuse.ch)
- Feodo Tracker (abuse.ch)
- MalwareBazaar (abuse.ch)
- URLhaus (abuse.ch)

Stores in SQLite with pre-compiled S1QL queries.
"""
import json
import httpx
import sqlite3
import os
import sys
import logging
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))
from database import get_db, init_db, DB_PATH
from ioc_extractor import IOCResult
from compiler import compile_ioc_query

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

FEEDS = {
    "CISA_KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "THREATFOX": "https://threatfox-api.abuse.ch/api/v1/",
    "FEODO": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "MALWAREBAZAAR": "https://mb-api.abuse.ch/api/v1/",
    "URLHAUS": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
}

def fetch_cisa_kev(client: httpx.Client, conn: sqlite3.Connection):
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    logger.info("Fetching CISA KEV...")
    try:
        r = client.get(FEEDS["CISA_KEV"], timeout=30.0)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])[:20]
        count = 0
        for v in vulns:
            title = f"{v.get('cveID','')} — {v.get('vendorProject','')} {v.get('product','')}"
            # Check if already exists
            existing = conn.execute("SELECT id FROM threat_feeds WHERE source='CISA_KEV' AND title=?", (title,)).fetchone()
            if existing:
                continue
            conn.execute(
                "INSERT INTO threat_feeds (source, severity, title, description, malware_family, mitre, iocs_json, precompiled_query, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("CISA_KEV", "CRITICAL", title,
                 v.get("shortDescription", v.get("vulnerabilityName", "")),
                 v.get("vendorProject", ""),
                 "[]", "{}", "",
                 (datetime.utcnow() + timedelta(days=30)).isoformat())
            )
            count += 1
        conn.commit()
        logger.info(f"CISA KEV: {count} new entries")
    except Exception as e:
        logger.error(f"CISA KEV failed: {e}")


def fetch_threatfox(client: httpx.Client, conn: sqlite3.Connection):
    """Fetch ThreatFox IOCs from last 3 days."""
    logger.info("Fetching ThreatFox...")
    try:
        r = client.post(FEEDS["THREATFOX"], json={"query": "get_iocs", "days": 3}, timeout=30.0)
        r.raise_for_status()
        data = r.json()
        iocs_raw = data.get("data", [])[:100]

        # Group by malware family
        grouped = {}
        for ioc in iocs_raw:
            key = ioc.get("malware", "Unknown")
            if key not in grouped:
                grouped[key] = {"mal": ioc.get("malware_printable", key), "items": []}
            grouped[key]["items"].append(ioc)

        count = 0
        for key, val in list(grouped.items())[:12]:
            title = f"{val['mal']} — {len(val['items'])} IOCs"
            existing = conn.execute("SELECT id FROM threat_feeds WHERE source='THREATFOX' AND title=?", (title,)).fetchone()
            if existing:
                continue

            ioc_data = {"sha256": [], "ips": [], "domains": []}
            for item in val["items"]:
                ioc_type = item.get("ioc_type", "")
                ioc_val = item.get("ioc", "")
                if "ip:port" in ioc_type:
                    ioc_data["ips"].append(ioc_val.split(":")[0])
                elif ioc_type == "domain":
                    ioc_data["domains"].append(ioc_val)
                elif "hash" in ioc_type:
                    ioc_data["sha256"].append(ioc_val)

            # Pre-compile query
            ioc_obj = IOCResult(sha256=ioc_data["sha256"], ips=ioc_data["ips"], domains=ioc_data["domains"])
            compiled = compile_ioc_query(ioc_obj)

            conn.execute(
                "INSERT INTO threat_feeds (source, severity, title, description, malware_family, mitre, iocs_json, precompiled_query, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("THREATFOX", "HIGH", title,
                 f"Active {val['mal']} indicators from ThreatFox",
                 val["mal"], "[]", json.dumps(ioc_data),
                 compiled.get("query", ""),
                 (datetime.utcnow() + timedelta(days=7)).isoformat())
            )
            count += 1
        conn.commit()
        logger.info(f"ThreatFox: {count} new entries")
    except Exception as e:
        logger.error(f"ThreatFox failed: {e}")


def fetch_feodo(client: httpx.Client, conn: sqlite3.Connection):
    """Fetch Feodo Tracker botnet C2 IPs."""
    logger.info("Fetching Feodo Tracker...")
    try:
        r = client.get(FEEDS["FEODO"], timeout=30.0)
        r.raise_for_status()
        data = r.json()

        grouped = {}
        for entry in (data or [])[:60]:
            key = entry.get("malware", "Unknown")
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(entry.get("ip_address", ""))

        count = 0
        for key, ips in list(grouped.items())[:6]:
            title = f"Feodo: {key} — {len(ips)} C2 IPs"
            existing = conn.execute("SELECT id FROM threat_feeds WHERE source='FEODO' AND title=?", (title,)).fetchone()
            if existing:
                continue

            ioc_data = {"ips": ips[:50]}
            ioc_obj = IOCResult(ips=ips[:50])
            compiled = compile_ioc_query(ioc_obj)

            conn.execute(
                "INSERT INTO threat_feeds (source, severity, title, description, malware_family, mitre, iocs_json, precompiled_query, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("FEODO", "CRITICAL", title,
                 f"Active {key} botnet C2 infrastructure. Updated daily.",
                 key, json.dumps(["T1071", "T1095", "T1573"]),
                 json.dumps(ioc_data), compiled.get("query", ""),
                 (datetime.utcnow() + timedelta(days=3)).isoformat())
            )
            count += 1
        conn.commit()
        logger.info(f"Feodo: {count} new entries")
    except Exception as e:
        logger.error(f"Feodo failed: {e}")


def fetch_malwarebazaar(client: httpx.Client, conn: sqlite3.Connection):
    """Fetch recent MalwareBazaar samples."""
    logger.info("Fetching MalwareBazaar...")
    try:
        r = client.post(FEEDS["MALWAREBAZAAR"],
                        data="query=get_recent&selector=50",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=30.0)
        r.raise_for_status()
        data = r.json()

        grouped = {}
        for s in (data.get("data") or [])[:50]:
            key = s.get("signature") or "Unknown"
            if key not in grouped:
                grouped[key] = {"hashes": [], "tags": s.get("tags") or []}
            grouped[key]["hashes"].append(s.get("sha256_hash", ""))

        count = 0
        for key, val in list(grouped.items())[:6]:
            title = f"{key} — {len(val['hashes'])} Samples"
            existing = conn.execute("SELECT id FROM threat_feeds WHERE source='MALWAREBAZAAR' AND title=?", (title,)).fetchone()
            if existing:
                continue

            ioc_data = {"sha256": val["hashes"][:10]}
            ioc_obj = IOCResult(sha256=val["hashes"][:10])
            compiled = compile_ioc_query(ioc_obj)

            conn.execute(
                "INSERT INTO threat_feeds (source, severity, title, description, malware_family, mitre, iocs_json, precompiled_query, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("MALWAREBAZAAR", "HIGH", title,
                 f"Recent {key} samples. Tags: {', '.join(val['tags'][:5]) or 'none'}",
                 key, "[]", json.dumps(ioc_data), compiled.get("query", ""),
                 (datetime.utcnow() + timedelta(days=7)).isoformat())
            )
            count += 1
        conn.commit()
        logger.info(f"MalwareBazaar: {count} new entries")
    except Exception as e:
        logger.error(f"MalwareBazaar failed: {e}")


def fetch_urlhaus(client: httpx.Client, conn: sqlite3.Connection):
    """Fetch recent URLhaus malware URLs."""
    logger.info("Fetching URLhaus...")
    try:
        r = client.post(FEEDS["URLHAUS"],
                        data="limit=30",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=30.0)
        r.raise_for_status()
        data = r.json()

        urls = data.get("urls", [])[:30]
        if not urls:
            return

        from urllib.parse import urlparse
        domains = list(set(urlparse(u.get("url", "")).hostname or "" for u in urls if u.get("url")))
        domains = [d for d in domains if d and d not in {"", "None"}]

        title = f"URLhaus — {len(urls)} Recent Malware URLs"
        existing = conn.execute("SELECT id FROM threat_feeds WHERE source='URLHAUS' AND title=?", (title,)).fetchone()
        if not existing and domains:
            ioc_data = {"domains": domains[:20]}
            ioc_obj = IOCResult(domains=domains[:20])
            compiled = compile_ioc_query(ioc_obj)

            conn.execute(
                "INSERT INTO threat_feeds (source, severity, title, description, malware_family, mitre, iocs_json, precompiled_query, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("URLHAUS", "HIGH", title,
                 f"Recently reported malware distribution URLs across {len(domains)} unique domains",
                 "", json.dumps(["T1566", "T1204"]),
                 json.dumps(ioc_data), compiled.get("query", ""),
                 (datetime.utcnow() + timedelta(days=3)).isoformat())
            )
            conn.commit()
            logger.info(f"URLhaus: 1 new entry ({len(domains)} domains)")
    except Exception as e:
        logger.error(f"URLhaus failed: {e}")


def cleanup_expired(conn: sqlite3.Connection):
    """Remove expired feed entries."""
    now = datetime.utcnow().isoformat()
    deleted = conn.execute("DELETE FROM threat_feeds WHERE expires_at < ?", (now,)).rowcount
    conn.commit()
    if deleted:
        logger.info(f"Cleaned up {deleted} expired feed entries")


def run_all_feeds():
    """Run all feed fetchers."""
    init_db()
    conn = get_db()
    client = httpx.Client()

    logger.info("=" * 60)
    logger.info("S1 Assistant — Threat Feed Sync")
    logger.info("=" * 60)

    cleanup_expired(conn)
    fetch_cisa_kev(client, conn)
    fetch_threatfox(client, conn)
    fetch_feodo(client, conn)
    fetch_malwarebazaar(client, conn)
    fetch_urlhaus(client, conn)

    total = conn.execute("SELECT COUNT(*) FROM threat_feeds").fetchone()[0]
    logger.info(f"Total threat entries in DB: {total}")
    logger.info("Feed sync complete")

    conn.close()
    client.close()


if __name__ == "__main__":
    run_all_feeds()
