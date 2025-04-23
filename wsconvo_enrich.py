#!/usr/bin/env python3
"""ip_enrich.py
Extend Wireshark **Conversations** CSV so the original columns stay intact *and* each row
gets per‑remote‑IP enrichment (DNS, ASN, org, etc.). The resulting CSV is a superset of
the input, so you can filter/sort without joining two files later.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import sys
import time
from functools import lru_cache
from typing import Dict, List, Tuple

import dns.resolver  # type: ignore
from ipwhois import IPWhois  # type: ignore
from ipwhois.exceptions import IPDefinedError

# ---------------------------------------------------------------------------
#  Constants / heuristics
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
#  Utility helpers
# ---------------------------------------------------------------------------

def is_private(ip: str) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return (
        any(ip_obj in net for net in PRIVATE_NETWORKS)
        or ip_obj.is_loopback
        or ip_obj.is_link_local
    )


@lru_cache(maxsize=2048)
def resolve_hostnames(ip: str, timeout: float = 3.0) -> List[str]:
    """Cached reverse DNS (PTR) lookup. Returns list (possibly empty)."""
    hostnames: List[str] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        rev = dns.reversename.from_address(ip)
        for rdata in resolver.resolve(rev, "PTR"):
            hostnames.append(str(rdata).rstrip("."))
    except Exception:
        pass
    return hostnames


def whois_lookup(ip: str, timeout: int = 10) -> Tuple[str, str, str]:
    """Return (asn, org, registry). Blank strings on failure."""
    try:
        obj = IPWhois(ip, timeout=timeout)
        rdap = obj.lookup_rdap(depth=1)
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
    combined = (",".join(hostnames) + org).lower()
    if any(k in combined for k in BENIGN_DOMAIN_KEYWORDS):
        return "likely_benign"
    return "review"

# ---------------------------------------------------------------------------
#  CSV processing
# ---------------------------------------------------------------------------

def load_target_rows(csv_path: str, target_ip: str) -> List[Dict[str, str]]:
    """Return only the rows where target_ip appears in either Address column."""
    rows: List[Dict[str, str]] = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_a = row.get("Address A", "").strip()
            ip_b = row.get("Address B", "").strip()
            if target_ip in (ip_a, ip_b):
                rows.append(row)
    return rows


def enrich_rows(
    rows: List[Dict[str, str]],
    target_ip: str,
    delay: float,
    use_heuristic: bool,
) -> None:
    """Mutates each row, appending enrichment columns for the *remote* IP."""
    for idx, row in enumerate(rows, 1):
        ip_a = row.get("Address A", "").strip()
        ip_b = row.get("Address B", "").strip()
        remote_ip = ip_b if ip_a == target_ip else ip_a
        row["remote_ip"] = remote_ip  # explicit column for clarity

        # Skip obviously blank
        if not remote_ip:
            continue

        # Enrichment
        hostnames = resolve_hostnames(remote_ip)
        asn, org, registry = whois_lookup(remote_ip)

        row["remote_hostnames"] = ";".join(hostnames)
        row["remote_asn"] = asn
        row["remote_org"] = org
        row["remote_registry"] = registry
        if use_heuristic:
            row["flag"] = heuristic_flag(hostnames, org, remote_ip)

        time.sleep(delay)

# ---------------------------------------------------------------------------
#  Entry
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Append DNS/WHOIS enrichment to each Wireshark Conversations row."
    )
    p.add_argument("-c", "--csv", required=True, help="Wireshark conversations CSV")
    p.add_argument("-t", "--target", required=True, help="Target IP address")
    p.add_argument("-o", "--output", default="enriched_report.csv")
    p.add_argument("--delay", type=float, default=1.0, help="Delay seconds between lookups")
    p.add_argument("--heuristic", action="store_true", help="Add benign/review flag")
    args = p.parse_args()

    # Validate target IP early
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        sys.exit("--target must be a valid IP address")

    rows = load_target_rows(args.csv, args.target)
    if not rows:
        sys.exit("Target IP not present in Conversations CSV.")

    enrich_rows(rows, args.target, args.delay, args.heuristic)

    # Preserve original order + new cols
    extra_cols = [
        "remote_ip",
        "remote_hostnames",
        "remote_asn",
        "remote_org",
        "remote_registry",
    ] + (["flag"] if args.heuristic else [])

    fieldnames = list(rows[0].keys()) + [col for col in extra_cols if col not in rows[0]]

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Enriched rows: {len(rows)}  →  {args.output}")


if __name__ == "__main__":
    main()

