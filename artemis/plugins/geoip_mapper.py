"""
GeoIP Mapper Plugin for Artemis

Maps external IP addresses from network connections to geographic locations.
Uses ip-api.com batch API (free, no key required) with persistent caching.
"""

import json
import time
import logging
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from collections import Counter

import requests

from artemis.plugins import ArtemisPlugin

logger = logging.getLogger("artemis.plugins.geoip")

# ip-api.com free tier: 45 requests/minute, batch of 100 IPs each
BATCH_API_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
RATE_LIMIT_DELAY = 1.5  # seconds between batch requests


def _is_external(ip_str: str) -> bool:
    """Check if an IP address is external (not private/reserved)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global
    except (ValueError, TypeError):
        return False


class GeoIPMapperPlugin(ArtemisPlugin):
    """Maps external IPs to geographic locations for world map visualization."""

    DESCRIPTION = "Geographic mapping of external network connections"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.cache_file = Path(config.get('cache_file', 'geoip_cache.json'))
        self.results_file = Path(config.get('results_dir', 'geoip_results')) / 'latest.json'
        self.cache: Dict[str, Dict] = {}
        self.last_results: Optional[Dict] = None

    def initialize(self):
        """Load cached GeoIP data."""
        self.results_file.parent.mkdir(exist_ok=True)
        self._load_cache()
        self.enabled = True
        logger.info(f"GeoIP Mapper initialized: {len(self.cache)} cached IPs")

    def _load_cache(self):
        """Load IP geolocation cache from disk."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    self.cache = json.load(f)
                logger.info(f"Loaded GeoIP cache: {len(self.cache)} entries")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP cache: {e}")
                self.cache = {}

    def _save_cache(self):
        """Save IP geolocation cache to disk."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.warning(f"Failed to save GeoIP cache: {e}")

    def _lookup_batch(self, ips: List[str]) -> Dict[str, Dict]:
        """Look up a batch of IPs via ip-api.com."""
        results = {}

        # Build request payload
        payload = [{"query": ip, "fields": "query,status,country,countryCode,regionName,city,lat,lon,isp,org,as"} for ip in ips]

        try:
            resp = requests.post(BATCH_API_URL, json=payload, timeout=10)
            resp.raise_for_status()
            data = resp.json()

            for entry in data:
                ip = entry.get('query', '')
                if entry.get('status') == 'success':
                    results[ip] = {
                        'country': entry.get('country', ''),
                        'country_code': entry.get('countryCode', ''),
                        'region': entry.get('regionName', ''),
                        'city': entry.get('city', ''),
                        'lat': entry.get('lat', 0),
                        'lon': entry.get('lon', 0),
                        'isp': entry.get('isp', ''),
                        'org': entry.get('org', ''),
                        'as': entry.get('as', ''),
                    }
                else:
                    results[ip] = {'error': 'lookup_failed'}

        except Exception as e:
            logger.warning(f"GeoIP batch lookup failed: {e}")
            for ip in ips:
                results[ip] = {'error': str(e)}

        return results

    def _resolve_ips(self, external_ips: Set[str]) -> Dict[str, Dict]:
        """Resolve all external IPs, using cache and batch API."""
        uncached = [ip for ip in external_ips if ip not in self.cache]

        if uncached:
            logger.info(f"GeoIP: {len(uncached)} uncached IPs to resolve ({len(self.cache)} cached)")
            # Batch lookup in chunks
            for i in range(0, len(uncached), BATCH_SIZE):
                batch = uncached[i:i + BATCH_SIZE]
                results = self._lookup_batch(batch)
                self.cache.update(results)

                if i + BATCH_SIZE < len(uncached):
                    time.sleep(RATE_LIMIT_DELAY)

            self._save_cache()

        return {ip: self.cache.get(ip, {'error': 'not_found'}) for ip in external_ips}

    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Process network data and map external IPs to locations.

        Expected kwargs:
            network_connections: List of connection records
            dns_queries: List of DNS query records
        """
        connections = kwargs.get('network_connections', [])
        dns_queries = kwargs.get('dns_queries', [])

        # Collect unique external IPs with connection counts
        ip_counts = Counter()
        ip_services = {}  # ip -> set of ports

        for conn in connections:
            if not isinstance(conn, dict):
                continue
            for ip_field in ('destination_ip', 'source_ip'):
                ip = conn.get(ip_field, '')
                if ip and _is_external(ip):
                    ip_counts[ip] += 1
                    port = conn.get('destination_port', '')
                    if port and ip_field == 'destination_ip':
                        ip_services.setdefault(ip, set()).add(str(port))

        for dns in dns_queries:
            if not isinstance(dns, dict):
                continue
            answer = dns.get('answer', '')
            if answer and _is_external(answer):
                ip_counts[answer] += 1

        if not ip_counts:
            result = {
                'timestamp': datetime.now().isoformat(),
                'total_external_ips': 0,
                'locations': [],
                'country_summary': {},
            }
            self.last_results = result
            return result

        external_ips = set(ip_counts.keys())
        logger.info(f"GeoIP: Processing {len(external_ips)} unique external IPs")

        # Resolve locations
        geo_data = self._resolve_ips(external_ips)

        # Build location entries
        locations = []
        country_counts = Counter()

        for ip, geo in geo_data.items():
            if 'error' in geo:
                continue

            country_counts[geo.get('country', 'Unknown')] += ip_counts[ip]
            services = sorted(ip_services.get(ip, set()))

            locations.append({
                'ip': ip,
                'lat': geo['lat'],
                'lon': geo['lon'],
                'country': geo.get('country', ''),
                'country_code': geo.get('country_code', ''),
                'city': geo.get('city', ''),
                'region': geo.get('region', ''),
                'isp': geo.get('isp', ''),
                'org': geo.get('org', ''),
                'as': geo.get('as', ''),
                'connection_count': ip_counts[ip],
                'services': services[:20],
            })

        # Sort by connection count descending
        locations.sort(key=lambda x: x['connection_count'], reverse=True)

        result = {
            'timestamp': datetime.now().isoformat(),
            'total_external_ips': len(external_ips),
            'resolved_ips': len([l for l in locations]),
            'locations': locations,
            'country_summary': dict(country_counts.most_common(50)),
            'top_talkers': [
                {'ip': l['ip'], 'country': l['country'], 'city': l['city'],
                 'connections': l['connection_count'], 'org': l['org']}
                for l in locations[:20]
            ],
        }

        self.last_results = result

        # Save results
        try:
            with open(self.results_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to save GeoIP results: {e}")

        logger.info(
            f"GeoIP: Mapped {len(locations)} IPs across "
            f"{len(country_counts)} countries"
        )
        return result

    def get_map_data(self) -> Dict:
        """Get the latest GeoIP results for map rendering."""
        if self.results_file.exists():
            try:
                with open(self.results_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return {'locations': [], 'country_summary': {}, 'total_external_ips': 0}

    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        return {
            'cached_ips': len(self.cache),
            'cache_file': str(self.cache_file),
            'cache_size_kb': round(self.cache_file.stat().st_size / 1024, 1) if self.cache_file.exists() else 0,
        }

    def cleanup(self):
        """Save cache on shutdown."""
        self._save_cache()
        self.enabled = False
        logger.info("GeoIP Mapper stopped")
