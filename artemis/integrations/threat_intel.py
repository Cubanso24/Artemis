"""
Threat Intelligence Enrichment Module for Artemis.

Queries free threat intel sources with built-in rate limiting and caching.
Supports optional paid API tokens for higher limits.

Sources (all free tier):
    - AbuseIPDB       (1,000 checks/day free)
    - VirusTotal      (4 req/min, 500/day free)
    - AlienVault OTX  (generous free tier)
    - GreyNoise       (50 community lookups/day)
    - ip-api.com      (45 req/min, GeoIP only)
"""

import json
import hashlib
import logging
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("artemis.threat_intel")


# ---------------------------------------------------------------------------
# Rate limiter — token-bucket per source
# ---------------------------------------------------------------------------

class RateLimiter:
    """Token-bucket rate limiter for API calls."""

    def __init__(self, calls_per_window: int, window_seconds: float):
        self.max_tokens = calls_per_window
        self.window = window_seconds
        self.tokens = float(calls_per_window)
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Block until a token is available or *timeout* seconds elapse."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.25)

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        refill = elapsed * (self.max_tokens / self.window)
        self.tokens = min(self.max_tokens, self.tokens + refill)
        self.last_refill = now


# ---------------------------------------------------------------------------
# Cache — SQLite backed, survives restarts
# ---------------------------------------------------------------------------

class IntelCache:
    """SQLite-backed cache for threat intel lookups."""

    def __init__(self, db_path: str = "artemis.db", ttl_hours: int = 24):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self._init_table()

    def _init_table(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_cache (
                cache_key TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                indicator TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_intel_cache_indicator
            ON intel_cache(indicator)
        """)
        conn.commit()
        conn.close()

    def get(self, source: str, indicator: str) -> Optional[Dict]:
        key = self._key(source, indicator)
        cutoff = (datetime.now() - timedelta(hours=self.ttl_hours)).isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT data FROM intel_cache "
                "WHERE cache_key = ? AND created_at > ?",
                (key, cutoff),
            ).fetchone()
            if row:
                return json.loads(row[0])
            return None
        finally:
            conn.close()

    def put(self, source: str, indicator: str, data: Dict):
        key = self._key(source, indicator)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO intel_cache "
                "(cache_key, source, indicator, data, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, source, indicator, json.dumps(data),
                 datetime.now().isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

    def get_all_for_indicator(self, indicator: str) -> Dict[str, Dict]:
        """Get cached results from all sources for an indicator."""
        cutoff = (datetime.now() - timedelta(hours=self.ttl_hours)).isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT source, data FROM intel_cache "
                "WHERE indicator = ? AND created_at > ?",
                (indicator, cutoff),
            ).fetchall()
            return {r[0]: json.loads(r[1]) for r in rows}
        finally:
            conn.close()

    def clear_expired(self):
        cutoff = (datetime.now() - timedelta(hours=self.ttl_hours)).isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "DELETE FROM intel_cache WHERE created_at <= ?", (cutoff,))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _key(source: str, indicator: str) -> str:
        raw = f"{source}:{indicator}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Source adapters
# ---------------------------------------------------------------------------

class _BaseSource:
    """Base class for threat intel source adapters."""
    name: str = "base"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.enabled = True

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        raise NotImplementedError

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        return None  # not all sources support domain lookups

    def _get(self, url: str, headers: Dict = None,
             params: Dict = None, timeout: int = 10) -> Optional[Dict]:
        if requests is None:
            logger.warning("requests library not installed")
            return None
        try:
            resp = requests.get(url, headers=headers or {},
                                params=params or {}, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                logger.warning(f"{self.name}: rate limited (429)")
            else:
                logger.debug(f"{self.name}: HTTP {resp.status_code} for {url}")
            return None
        except Exception as e:
            logger.debug(f"{self.name} error: {e}")
            return None


class AbuseIPDBSource(_BaseSource):
    """AbuseIPDB — free tier: 1,000 checks/day."""
    name = "abuseipdb"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        data = self._get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
        if not data or "data" not in data:
            return None
        d = data["data"]
        return {
            "source": self.name,
            "ip": ip,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "is_public": d.get("isPublic", True),
            "last_reported": d.get("lastReportedAt"),
            "categories": d.get("reports", [])[:5],
        }


class VirusTotalSource(_BaseSource):
    """VirusTotal — free tier: 4 req/min, 500/day."""
    name = "virustotal"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        data = self._get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.api_key},
        )
        if not data or "data" not in data:
            return None
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": self.name,
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "asn": attrs.get("asn"),
            "reputation": attrs.get("reputation", 0),
        }

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        data = self._get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": self.api_key},
        )
        if not data or "data" not in data:
            return None
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": self.name,
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar", ""),
            "creation_date": attrs.get("creation_date"),
        }


class AlienVaultOTXSource(_BaseSource):
    """AlienVault OTX — generous free tier."""
    name = "otx"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        data = self._get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers,
        )
        if not data:
            return None
        return {
            "source": self.name,
            "ip": ip,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "reputation": data.get("reputation", 0),
            "country": data.get("country_code", ""),
            "asn": data.get("asn", ""),
            "pulses": [
                p.get("name", "")
                for p in (data.get("pulse_info", {})
                          .get("pulses", []))[:5]
            ],
        }

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        data = self._get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers,
        )
        if not data:
            return None
        return {
            "source": self.name,
            "domain": domain,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "alexa": data.get("alexa", ""),
            "whois": (data.get("whois") or "")[:200],
        }


class GreyNoiseSource(_BaseSource):
    """GreyNoise Community — 50 lookups/day free."""
    name = "greynoise"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        url = "https://api.greynoise.io/v3/community/" + ip
        headers = {}
        if self.api_key:
            headers["key"] = self.api_key
        data = self._get(url, headers=headers)
        if not data:
            return None
        return {
            "source": self.name,
            "ip": ip,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "message": data.get("message", ""),
            "last_seen": data.get("last_seen", ""),
        }


class GeoIPSource(_BaseSource):
    """ip-api.com — 45 req/min, free for non-commercial. No key needed."""
    name = "geoip"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        data = self._get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,region,regionName,"
                    "city,zip,lat,lon,timezone,isp,org,as,asname,query"},
        )
        if not data or data.get("status") != "success":
            return None
        return {
            "source": self.name,
            "ip": ip,
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as_number": data.get("as", ""),
            "as_name": data.get("asname", ""),
        }


# ---------------------------------------------------------------------------
# Main ThreatIntelManager
# ---------------------------------------------------------------------------

class ThreatIntelManager:
    """
    Orchestrates threat intel lookups across all configured sources.

    Usage:
        mgr = ThreatIntelManager()
        mgr.configure({"virustotal_key": "abc123"})
        result = mgr.enrich_ip("8.8.8.8")
    """

    # Default rate limits per source (free tiers)
    DEFAULT_LIMITS = {
        "abuseipdb":  (1000, 86400),   # 1,000/day
        "virustotal": (4, 60),         # 4/min
        "otx":        (100, 60),       # ~100/min
        "greynoise":  (50, 86400),     # 50/day
        "geoip":      (45, 60),        # 45/min
    }

    def __init__(self, db_path: str = "artemis.db", cache_ttl_hours: int = 24):
        self.cache = IntelCache(db_path=db_path, ttl_hours=cache_ttl_hours)
        self.sources: Dict[str, _BaseSource] = {}
        self.limiters: Dict[str, RateLimiter] = {}
        self._config: Dict[str, str] = {}
        self._config_path = Path("config/threat_intel.json")

        # Load saved config
        self._load_config()

        # Always register sources that work without a key
        self._register_source("geoip", GeoIPSource())
        self._register_source("otx", AlienVaultOTXSource())

    def configure(self, settings: Dict[str, str]):
        """
        Configure API keys. Keys:
            abuseipdb_key, virustotal_key, otx_key, greynoise_key
        """
        self._config.update(settings)
        self._save_config()

        key_map = {
            "abuseipdb_key": ("abuseipdb", AbuseIPDBSource),
            "virustotal_key": ("virustotal", VirusTotalSource),
            "otx_key": ("otx", AlienVaultOTXSource),
            "greynoise_key": ("greynoise", GreyNoiseSource),
        }

        for config_key, (name, cls) in key_map.items():
            api_key = self._config.get(config_key)
            if api_key:
                self._register_source(name, cls(api_key=api_key))

        # OTX works without a key too
        if "otx" not in self.sources:
            self._register_source("otx", AlienVaultOTXSource())

    def _register_source(self, name: str, source: _BaseSource):
        self.sources[name] = source
        if name in self.DEFAULT_LIMITS:
            calls, window = self.DEFAULT_LIMITS[name]
            self.limiters[name] = RateLimiter(calls, window)

    def _load_config(self):
        if self._config_path.exists():
            try:
                self._config = json.loads(self._config_path.read_text())
                self.configure(self._config)
            except Exception as e:
                logger.warning(f"Failed to load threat intel config: {e}")

    def _save_config(self):
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            self._config_path.write_text(
                json.dumps(self._config, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save threat intel config: {e}")

    def get_config_status(self) -> Dict[str, Any]:
        """Return current configuration state for the UI."""
        status = {}
        for name in ["abuseipdb", "virustotal", "otx", "greynoise", "geoip"]:
            source = self.sources.get(name)
            has_key = bool(self._config.get(f"{name}_key"))
            status[name] = {
                "enabled": source is not None and source.enabled,
                "has_api_key": has_key or name == "geoip",
                "requires_key": name not in ("geoip", "otx"),
            }
        return status

    def enrich_ip(self, ip: str, sources: List[str] = None) -> Dict[str, Any]:
        """
        Enrich an IP across all (or specified) sources.
        Returns cached results when available.
        """
        if self._is_private_ip(ip):
            return {
                "ip": ip,
                "private": True,
                "sources": {},
                "verdict": "internal",
            }

        target_sources = sources or list(self.sources.keys())
        results = {}
        any_fetched = False

        for name in target_sources:
            source = self.sources.get(name)
            if not source or not source.enabled:
                continue

            # Check cache first
            cached = self.cache.get(name, ip)
            if cached is not None:
                results[name] = cached
                continue

            # Rate limit
            limiter = self.limiters.get(name)
            if limiter and not limiter.acquire(timeout=5):
                logger.debug(f"{name}: rate limited, skipping {ip}")
                continue

            data = source.lookup_ip(ip)
            if data:
                self.cache.put(name, ip, data)
                results[name] = data
                any_fetched = True

        return {
            "ip": ip,
            "private": False,
            "sources": results,
            "verdict": self._compute_verdict(results),
            "enriched_at": datetime.now().isoformat(),
        }

    def enrich_domain(self, domain: str,
                      sources: List[str] = None) -> Dict[str, Any]:
        """Enrich a domain across all (or specified) sources."""
        target_sources = sources or list(self.sources.keys())
        results = {}

        for name in target_sources:
            source = self.sources.get(name)
            if not source or not source.enabled:
                continue

            cached = self.cache.get(name, domain)
            if cached is not None:
                results[name] = cached
                continue

            limiter = self.limiters.get(name)
            if limiter and not limiter.acquire(timeout=5):
                continue

            data = source.lookup_domain(domain)
            if data:
                self.cache.put(name, domain, data)
                results[name] = data

        return {
            "domain": domain,
            "sources": results,
            "verdict": self._compute_verdict(results),
            "enriched_at": datetime.now().isoformat(),
        }

    def enrich_batch(self, indicators: List[str],
                     indicator_type: str = "ip") -> List[Dict[str, Any]]:
        """Enrich a batch of indicators. Respects rate limits automatically."""
        results = []
        fn = self.enrich_ip if indicator_type == "ip" else self.enrich_domain
        for ind in indicators:
            results.append(fn(ind))
        return results

    def _compute_verdict(self, results: Dict[str, Dict]) -> str:
        """Aggregate source results into a single verdict."""
        score = 0

        abuseipdb = results.get("abuseipdb")
        if abuseipdb:
            abuse_score = abuseipdb.get("abuse_score", 0)
            if abuse_score >= 80:
                score += 3
            elif abuse_score >= 50:
                score += 2
            elif abuse_score >= 25:
                score += 1

        vt = results.get("virustotal")
        if vt:
            mal = vt.get("malicious", 0)
            if mal >= 5:
                score += 3
            elif mal >= 2:
                score += 2
            elif mal >= 1:
                score += 1

        otx = results.get("otx")
        if otx:
            pulses = otx.get("pulse_count", 0)
            if pulses >= 10:
                score += 2
            elif pulses >= 3:
                score += 1

        gn = results.get("greynoise")
        if gn:
            classification = gn.get("classification", "")
            if classification == "malicious":
                score += 3
            elif classification == "unknown" and gn.get("noise"):
                score += 1

        if score >= 6:
            return "malicious"
        elif score >= 3:
            return "suspicious"
        elif score >= 1:
            return "low_risk"
        return "clean"

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is RFC 1918 / loopback / link-local."""
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return True
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 127:
            return True
        if octets[0] == 169 and octets[1] == 254:
            return True
        return False


# Singleton
threat_intel_manager = ThreatIntelManager()
