# ip_enrich

Small CLI to enrich Wireshark **Statistics → Conversations** CSV for a single target
device.

| Feature | Flag | Column(s) added |
|---------|------|-----------------|
|Reverse-DNS + RDAP (ASN/org) | _always on_ | `remote_hostnames`, `remote_asn`, `remote_org`, `remote_registry` |
|Heuristic benign/review tag | `--heuristic` | `flag` |
|Country / City / Anonymous-IP | `--with-geo` | `country`, `city`, `is_anonymous_ip` |
|AbuseIPDB reputation (cached) | `--with-reputation` | `abuse_score` |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ABUSEIPDB_KEY="your-api-key"

python wsconvo_enrich.py -c conversations.csv -t 10.0.0.42 \
        --heuristic \
        --with-geo --city-db ~/GeoLite2-City.mmdb --anon-db ~/GeoLite2-Anonymous-IP.mmdb \
        --with-reputation \
        -o enriched_report.csv
```

See python ip_enrich.py -h for all options.

## GeoLite2 databases
Download free MaxMind GeoLite2-City and GeoLite2-Anonymous-IP databases: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Store them somewhere readable and point --city-db / --anon-db at those files.

## Caching
AbuseIPDB lookups are cached in rep_cache.json (path configurable) so reruns don’t exhaust the daily quota.
