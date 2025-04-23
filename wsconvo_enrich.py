#!/usr/bin/env python3
"""wsconvo_enrich.py ‑‑ v0.3

Extends a Wireshark *Conversations* CSV so you keep every original column **plus**
optional enrichment:

* Reverse‑DNS hostname(s)
* ASN / Org / Registry (RDAP)
* **GeoIP** (country, city, anonymous‑IP flag)  [--with‑geo]
* **IP‑reputation** via AbuseIPDB  [--with‑reputation]
    · Only queried for rows tagged *review* by the heuristic
    · Results cached on disk (JSON) to spare your daily quota

Dependencies:
    pip install dnspython ipwhois geoip2 requests
    # and download MaxMind GeoLite2‑City.mmdb / GeoLite2‑Anonymous‑IP.mmdb

Set your AbuseIPDB key in env var **ABUSEIPDB_KEY**.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Tuple

import dns.resolver  # type: ignore
import requests  # type: ignore
from ipwhois import IPWhois  # type: ignore
from ipwhois.exceptions import IPDefinedError

# ---------------------------- Constants ---------------------------- #
BENIGN_DOMAIN_KEYWORDS = [
    "amazonaws.com",
    "google.com",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "facebook.com",
    "akamai",
]
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]
ABUSE_API_KEY = os.getenv("ABUSEIPDB_KEY")
ABUSE_API_URL = "https://api.abuseipdb.com/api/v2/check"

# ---------------------------- GeoIP (optional) ---------------------------- #
try:
    import geoip2.database  # type: ignore
except ModuleNotFoundError:  # graceful degrade
    geoip2 = None  # type: ignore


def build_geo_readers(city_db: str | None, anon_db: str | None):
    """Return (city_reader, anon_reader) or (None, None) if dbs unavailable."""
    if not geoip2:
        return None, None
    readers = []
    for path in (city_db, anon_db):
        if path and Path(path).is_file():
            readers.append(geoip2.database.Reader(path))
        else:
            readers.append(None)
    return tuple(readers)  # type: ignore


# ---------------------------- Helper funcs ---------------------------- #

def is_private(ip: str) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return (
        any(ip_obj in net for net in PRIVATE_NETWORKS)
        or ip_obj.is_loopback
        or ip_obj.is_link_local
    )


@lru_cache(maxsize=2048)
def resolve_hostnames(ip: str, timeout: float = 3.0) -> List[str]:
    hostnames: List[str] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        rev = dns.reversename.from_address(ip)
        hostnames = [str(r).rstrip(".") for r in resolver.resolve(rev, "PTR")]
    except Exception:
        pass
    return hostnames


def whois_lookup(ip: str, timeout: int = 10) -> Tuple[str, str, str]:
    try:
        rdap = IPWhois(ip, timeout=timeout).lookup_rdap(depth=1)
        asn = rdap.get("asn", "")
        org = rdap.get("network", {}).get("name", "") or rdap.get(
            "asn_description", ""
        )
        registry = rdap.get("asn_registry", "")
        return asn, org, registry
    except IPDefinedError:
        return "PRIVATE", "Private/Reserved", ""
    except Exception:
        return "", "", ""


def heuristic_flag(hostnames: List[str], org: str, ip: str) -> str:
    if is_private(ip):
        return "private"
    combo = (",".join(hostnames) + org).lower()
    if any(k in combo for k in BENIGN_DOMAIN_KEYWORDS):
        return "likely_benign"
    return "review"

# ---------------------------- Reputation ---------------------------- #

def load_cache(cache_path: Path) -> Dict[str, Dict]:
    if cache_path.is_file():
        with cache_path.open() as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_cache(cache: Dict[str, Dict], cache_path: Path):
    tmp = cache_path.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(cache, f)
    tmp.replace(cache_path)


def abuse_lookup(ip: str, cache: Dict, max_age: int = 30) -> int | None:
    """Return abuseConfidenceScore (0‑100) or None on failure / disabled."""
    if ip in cache:
        return cache[ip]["score"]
    if not ABUSE_API_KEY:
        return None
    try:
        rsp = requests.get(
            ABUSE_API_URL,
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age},
            timeout=8,
        )
        data = rsp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
    except Exception:
        score = None
    cache[ip] = {"score": score, "ts": int(time.time())}
    return score

# ---------------------------- CSV workflow ---------------------------- #

def load_target_rows(csv_path: str, target_ip: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if target_ip in (row.get("Address A", "").strip(), row.get("Address B", "").strip()):
                rows.append(row)
    return rows


def enrich_rows(
    rows: List[Dict[str, str]],
    target_ip: str,
    delay: float,
    use_heuristic: bool,
    use_geo: bool,
    city_reader,
    anon_reader,
    use_rep: bool,
    rep_cache: Dict[str, Dict],
):
    for row in rows:
        ip_a = row.get("Address A", "").strip()
        ip_b = row.get("Address B", "").strip()
        remote_ip = ip_b if ip_a == target_ip else ip_a
        row["remote_ip"] = remote_ip

        if not remote_ip:
            continue

        hostnames = resolve_hostnames(remote_ip)
        asn, org, registry = whois_lookup(remote_ip)
        row.update(
            {
                "remote_hostnames": ";".join(hostnames),
                "remote_asn": asn,
                "remote_org": org,
                "remote_registry": registry,
            }
        )

        # Heuristic flag first
        flag = heuristic_flag(hostnames, org, remote_ip) if use_heuristic else ""
        if use_heuristic:
            row["flag"] = flag

        # GeoIP (always safe)
        if use_geo and city_reader:
            try:
                geo = city_reader.city(remote_ip)
                row["country"] = geo.country.iso_code or ""
                row["city"] = geo.city.name or ""
            except Exception:
                row["country"] = row["city"] = ""
        if use_geo and anon_reader:
            try:
                anon = anon_reader.anonymous_ip(remote_ip)
                row["is_anonymous_ip"] = str(anon.is_anonymous)
            except Exception:
                row["is_anonymous_ip"] = ""

        # Reputation only for "review" lines
        if use_rep and flag == "review":
            score = abuse_lookup(remote_ip, rep_cache)
            row["abuse_score"] = "" if score is None else str(score)

        time.sleep(delay)

# ---------------------------- Main ---------------------------- #

def main():
    p = argparse.ArgumentParser(description="Wireshark Conversations enrichment tool")
    p.add_argument("-c", "--csv", required=True)
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-o", "--output", default="enriched_report.csv")
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--heuristic", action="store_true")
    p.add_argument("--with-geo", action="store_true", help="Add GeoIP columns")
    p.add_argument("--city-db", help="Path to GeoLite2-City.mmdb")
    p.add_argument("--anon-db", help="Path to GeoLite2-Anonymous-IP.mmdb")
    p.add_argument("--with-reputation", action="store_true", help="Add AbuseIPDB score (review rows only)")
    p.add_argument("--rep-cache", default="rep_cache.json", help="Reputation cache file path")
    args = p.parse_args()

    # Validate target IP
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        sys.exit("Target IP must be valid")

    rows = load_target_rows(args.csv, args.target)
    if not rows:
        sys.exit("Target IP not present in CSV")

    city_reader, anon_reader = build_geo_readers(args.city_db, args.anon_db) if args.with_geo else (None, None)

    rep_cache_path = Path(args.rep_cache)
    rep_cache = load_cache(rep_cache_path) if args.with_reputation else {}

    enrich_rows(
        rows,
        args.target,
        args.delay,
        args.heuristic,
        args.with_geo,
        city_reader,
        anon_reader,
        args.with_reputation,
        rep_cache,
    )

    # Persist cache (only if modified)
    if args.with_reputation:
        save_cache(rep_cache, rep_cache_path)

    # Write CSV
    extra = [
        "remote_ip",
        "remote_hostnames",
        "remote_asn",
        "remote_org",
        "remote_registry",
    ]
    if args.heuristic:
        extra.append("flag")
    if args.with_geo:
        extra += ["country", "city", "is_anonymous_ip"]
    if args.with_reputation:
        extra.append("abuse_score")

    fieldnames = list(rows[0].keys()) + [c for c in extra if c not in rows[0]]
    with open(args.output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows)

    print(f"Enriched rows: {len(rows)}  →  {args.output}")


if __name__ == "__main__":
    main()

