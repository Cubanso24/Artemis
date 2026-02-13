"""
Data pipeline for orchestrating data collection from multiple sources.

Coordinates Splunk, Security Onion, and PCAP analysis to provide
comprehensive data to Artemis hunting agents.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import concurrent.futures
from dataclasses import dataclass

from artemis.integrations.splunk_connector import SplunkConnector
from artemis.integrations.security_onion_connector import SecurityOnionConnector
from artemis.integrations.pcap_analyzer import PCAPAnalyzer
from artemis.utils.logging_config import ArtemisLogger


@dataclass
class DataSourceConfig:
    """Configuration for data sources."""
    splunk_host: str = ""
    splunk_port: int = 8089
    splunk_token: str = ""
    splunk_username: str = ""
    splunk_password: str = ""
    splunk_verify_ssl: bool = False

    security_onion_host: str = ""
    security_onion_api_key: str = ""
    security_onion_username: str = ""
    security_onion_password: str = ""

    enable_pcap_analysis: bool = True
    enable_zeek_logs: bool = True
    enable_suricata_alerts: bool = True


class DataPipeline:
    """
    Orchestrates data collection from all sources.

    Provides unified interface for gathering threat hunting data
    from Splunk, Security Onion, and PCAP analysis.
    """

    def __init__(self, config: DataSourceConfig):
        """
        Initialize data pipeline.

        Args:
            config: Data source configuration
        """
        self.logger = ArtemisLogger.setup_logger("artemis.integrations.pipeline")
        self.config = config

        # Initialize connectors
        self.splunk = None
        self.security_onion = None
        self.pcap_analyzer = None

        self._init_connectors()

    def _init_connectors(self):
        """Initialize data source connectors."""
        # Splunk
        if self.config.splunk_host:
            try:
                self.splunk = SplunkConnector(
                    host=self.config.splunk_host,
                    port=self.config.splunk_port,
                    token=self.config.splunk_token,
                    username=self.config.splunk_username,
                    password=self.config.splunk_password,
                    verify_ssl=self.config.splunk_verify_ssl
                )
                self.logger.info("Splunk connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Splunk: {e}")

        # Security Onion
        if self.config.security_onion_host:
            try:
                self.security_onion = SecurityOnionConnector(
                    host=self.config.security_onion_host,
                    api_key=self.config.security_onion_api_key,
                    username=self.config.security_onion_username,
                    password=self.config.security_onion_password
                )
                self.logger.info("Security Onion connector initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Security Onion: {e}")

        # PCAP Analyzer
        if self.config.enable_pcap_analysis:
            try:
                self.pcap_analyzer = PCAPAnalyzer()
                self.logger.info("PCAP analyzer initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize PCAP analyzer: {e}")

    def collect_hunting_data(
        self,
        time_range: str = "-1h",
        include_pcap: bool = False,
        suspicious_ips: Optional[List[str]] = None,
        progress_callback=None,
        storage_mode: str = "ram",
    ) -> Dict[str, Any]:
        """
        Collect comprehensive hunting data from all sources.

        Args:
            time_range: Time range for data collection (e.g., "-1h", "-24h")
            include_pcap: Whether to retrieve and analyze PCAP
            suspicious_ips: Optional list of IPs to focus on
            progress_callback: Optional callable(info_dict) for live progress updates
            storage_mode: "ram" (default) keeps events in Python lists.
                          "sqlite" spills to a temp SQLite file so very
                          large collections don't exhaust memory.

        Returns:
            Hunting data (dict or SqliteEventStore).
        """
        self.logger.info(
            f"Collecting hunting data for time range: {time_range} "
            f"(storage={storage_mode})"
        )

        use_sqlite = storage_mode == "sqlite"
        if use_sqlite:
            from artemis.integrations.event_store import SqliteEventStore
            hunting_data = SqliteEventStore()
        else:
            hunting_data = {}

        # Collect from Splunk (if available).
        # When using SQLite storage the Splunk collector writes directly
        # into the store so per-window data is freed immediately.
        if self.splunk:
            self._collect_from_splunk(
                time_range, progress_callback=progress_callback,
                store=hunting_data,
            )

        # Collect from Security Onion
        if self.security_onion:
            so_data = self._collect_from_security_onion(
                time_range,
                include_pcap,
                suspicious_ips
            )
            hunting_data.update(so_data)

        # Merge and deduplicate (only for plain dicts — the SQLite store
        # accumulates via extend() and doesn't need a separate merge pass).
        if isinstance(hunting_data, dict):
            hunting_data = self._merge_data_sources(hunting_data)

        if hasattr(hunting_data, 'total_count'):
            total_events = hunting_data.total_count()
        else:
            total_events = sum(
                len(v) if isinstance(v, list) else 0
                for v in hunting_data.values()
            )
        self.logger.info(f"Collected {total_events} total events")

        return hunting_data

    # ------------------------------------------------------------------
    # Time-range helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_time_range_hours(time_range: str) -> float:
        """
        Parse a Splunk-style relative time range into total hours.

        Supports: -Ns, -Nm, -Nh, -Nd, -Nw, -Nmon
        Returns 0 if the range cannot be parsed (treated as <= 24h).
        """
        m = re.match(r'^-(\d+)(s|m|h|d|w|mon)$', time_range.strip())
        if not m:
            return 0

        value = int(m.group(1))
        unit = m.group(2)
        multipliers = {
            's': 1 / 3600,
            'm': 1 / 60,
            'h': 1,
            'd': 24,
            'w': 168,
            'mon': 720,
        }
        return value * multipliers.get(unit, 0)

    @staticmethod
    def _generate_time_windows(
        time_range: str,
        window_hours: int = 24,
    ) -> List[Tuple[str, str]]:
        """
        Split a large time range into fixed-size windows.

        Returns a list of (earliest_iso, latest_iso) pairs that Splunk
        accepts as absolute timestamps.  Windows are generated from the
        oldest time forward to "now".
        """
        m = re.match(r'^-(\d+)(s|m|h|d|w|mon)$', time_range.strip())
        if not m:
            # Cannot parse — return as single window
            return [(time_range, "now")]

        value = int(m.group(1))
        unit = m.group(2)
        unit_seconds = {
            's': 1, 'm': 60, 'h': 3600,
            'd': 86400, 'w': 604800, 'mon': 2592000,
        }

        total_seconds = value * unit_seconds.get(unit, 3600)
        window_seconds = window_hours * 3600

        now = datetime.utcnow()
        start = now - timedelta(seconds=total_seconds)

        windows = []
        cursor = start
        while cursor < now:
            window_end = min(cursor + timedelta(seconds=window_seconds), now)
            windows.append((
                cursor.strftime('%Y-%m-%dT%H:%M:%S'),
                window_end.strftime('%Y-%m-%dT%H:%M:%S'),
            ))
            cursor = window_end

        return windows

    # ------------------------------------------------------------------
    # Splunk collection
    # ------------------------------------------------------------------

    def _collect_from_splunk(self, time_range: str, progress_callback=None,
                             store=None) -> None:
        """
        Collect data from Splunk and merge into *store*.

        For time ranges > 24 hours, the query is broken into 24-hour
        windows so the Splunk search head isn't overwhelmed by a single
        massive job.  Each window's per-type queries run in parallel,
        then results are merged into *store* before the next window so
        that per-window memory is freed immediately (important when
        *store* is a SqliteEventStore).

        Args:
            time_range: Time range for queries (e.g. "-1h", "-30d")
            progress_callback: Optional callable(info_dict) for progress updates
            store: Dict-like container to merge results into.  Must support
                   ``.update(dict)`` and, for count helpers,
                   ``.count(key)`` / ``.total_count()``.
        """
        total_hours = self._parse_time_range_hours(time_range)

        if total_hours <= 24:
            # Short range — single pass
            window = self._collect_splunk_window(
                time_range, "now", progress_callback=progress_callback,
            )
            store.update(window)
            return

        # Long range — split into 24h windows
        windows = self._generate_time_windows(time_range, window_hours=24)
        self.logger.info(
            f"Large time range ({time_range} = {total_hours:.0f}h): "
            f"splitting into {len(windows)} x 24h windows"
        )

        for idx, (earliest, latest) in enumerate(windows, 1):
            self.logger.info(
                f"  Window {idx}/{len(windows)}: {earliest} → {latest}"
            )

            window_data = self._collect_splunk_window(
                earliest, latest,
                progress_callback=progress_callback,
                window_index=idx,
                total_windows=len(windows),
            )

            window_total = sum(
                len(v) for v in window_data.values() if isinstance(v, list)
            )

            # Merge into the caller's store — for SqliteEventStore this
            # writes to disk and frees the per-window dict.
            store.update(window_data)

            # Compute running total from the store
            if hasattr(store, 'total_count'):
                running_total = store.total_count()
                events_by_type = store.counts_by_type()
            else:
                running_total = sum(
                    len(v) for v in store.values() if isinstance(v, list)
                )
                events_by_type = {
                    k: len(v) for k, v in store.items() if isinstance(v, list)
                }

            self.logger.info(
                f"    Window {idx} returned {window_total} events "
                f"(running total: {running_total})"
            )

            if progress_callback:
                progress_callback({
                    'type': 'window_done',
                    'window': idx,
                    'total_windows': len(windows),
                    'window_events': window_total,
                    'running_total': running_total,
                    'events_by_type': events_by_type,
                })

    def _collect_splunk_window(
        self,
        earliest: str,
        latest: str,
        progress_callback=None,
        window_index: int = 1,
        total_windows: int = 1,
    ) -> Dict[str, Any]:
        """
        Collect all data types from Splunk for a single time window.

        Args:
            earliest: Start time (relative like "-1h" or absolute ISO timestamp)
            latest: End time ("now" or absolute ISO timestamp)
            progress_callback: Optional callable for progress updates
            window_index: Current window number (1-based)
            total_windows: Total number of windows

        Returns:
            Dict keyed by data type, values are event lists
        """
        data: Dict[str, Any] = {}
        query_names = [
            "network_connections", "dns_queries", "ntlm_logs",
            "authentication_logs",
            "process_logs", "powershell_logs", "file_operations",
            "scheduled_tasks", "registry_changes",
        ]
        completed_queries = {}

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = {
                    "network_connections": executor.submit(
                        self.splunk.get_network_connections, earliest, None, latest
                    ),
                    "dns_queries": executor.submit(
                        self.splunk.get_dns_queries, earliest, latest
                    ),
                    "ntlm_logs": executor.submit(
                        self.splunk.get_ntlm_logs, earliest, latest
                    ),
                    "authentication_logs": executor.submit(
                        self.splunk.get_authentication_logs, earliest, latest
                    ),
                    "process_logs": executor.submit(
                        self.splunk.get_process_logs, earliest, None, latest
                    ),
                    "powershell_logs": executor.submit(
                        self.splunk.get_powershell_logs, earliest, latest
                    ),
                    "file_operations": executor.submit(
                        self.splunk.get_file_operations, earliest, latest
                    ),
                    "scheduled_tasks": executor.submit(
                        self.splunk.get_scheduled_tasks, earliest, latest
                    ),
                    "registry_changes": executor.submit(
                        self.splunk.get_registry_changes, earliest, latest
                    ),
                }

                # Map future -> key so we can process in completion order
                future_to_key = {f: k for k, f in futures.items()}

                for future in concurrent.futures.as_completed(
                    future_to_key.keys(), timeout=3600
                ):
                    key = future_to_key[future]
                    try:
                        data[key] = future.result()
                        completed_queries[key] = len(data[key])

                        # Report per-query progress
                        if progress_callback:
                            progress_callback({
                                'type': 'query_done',
                                'query_name': key,
                                'query_events': len(data[key]),
                                'completed_queries': dict(completed_queries),
                                'queries_done': len(completed_queries),
                                'queries_total': len(query_names),
                                'window': window_index,
                                'total_windows': total_windows,
                            })

                    except Exception as e:
                        import traceback
                        self.logger.error(f"Failed to collect {key}: {e}")
                        self.logger.error(f"Traceback: {traceback.format_exc()}")
                        data[key] = []

        except Exception as e:
            self.logger.error(f"Splunk window collection failed: {e}")

        return data

    def _collect_from_security_onion(
        self,
        time_range: str,
        include_pcap: bool,
        suspicious_ips: Optional[List[str]]
    ) -> Dict[str, Any]:
        """
        Collect data from Security Onion.

        Args:
            time_range: Time range for collection
            include_pcap: Whether to analyze PCAP
            suspicious_ips: IPs to focus on

        Returns:
            Security Onion data dictionary
        """
        self.logger.info("Collecting data from Security Onion...")

        data = {}

        try:
            # Get Zeek logs
            if self.config.enable_zeek_logs:
                zeek_conn = self.security_onion.get_zeek_logs("conn")
                zeek_dns = self.security_onion.get_zeek_logs("dns")
                zeek_http = self.security_onion.get_zeek_logs("http")

                data["zeek_connections"] = zeek_conn
                data["zeek_dns"] = zeek_dns
                data["zeek_http"] = zeek_http

            # Get Suricata alerts
            if self.config.enable_suricata_alerts:
                alerts = self.security_onion.get_suricata_alerts()
                data["suricata_alerts"] = alerts

            # Analyze PCAP if requested
            if include_pcap and self.pcap_analyzer:
                pcap_data = self._analyze_pcap_for_ips(suspicious_ips)
                data.update(pcap_data)

        except Exception as e:
            self.logger.error(f"Security Onion data collection failed: {e}")

        return data

    def _analyze_pcap_for_ips(
        self,
        suspicious_ips: Optional[List[str]]
    ) -> Dict[str, Any]:
        """
        Retrieve and analyze PCAP for suspicious IPs.

        Args:
            suspicious_ips: List of IPs to investigate

        Returns:
            PCAP analysis results
        """
        if not suspicious_ips:
            return {}

        pcap_data = {}

        for ip in suspicious_ips:
            try:
                self.logger.info(f"Retrieving PCAP for IP: {ip}")

                # Get PCAP from Security Onion
                pcap_path = self.security_onion.get_pcap_for_ip(ip, time_range_hours=1)

                if pcap_path:
                    # Analyze PCAP
                    analysis = self.pcap_analyzer.analyze_pcap(pcap_path)

                    # Merge into main data
                    for key, value in analysis.items():
                        if key not in pcap_data:
                            pcap_data[key] = []
                        pcap_data[key].extend(value)

                    # Cleanup
                    self.security_onion.cleanup_pcap(pcap_path)

            except Exception as e:
                self.logger.error(f"PCAP analysis failed for {ip}: {e}")

        return pcap_data

    @staticmethod
    def _dedup_events(events: List[Dict], key_fields: List[str]) -> List[Dict]:
        """
        Deduplicate a list of event dicts by a composite key.

        Args:
            events: List of event dicts
            key_fields: Fields to use as the dedup key

        Returns:
            Deduplicated list (preserves first occurrence)
        """
        seen = set()
        deduped = []
        for event in events:
            key = tuple(str(event.get(f, '')) for f in key_fields)
            if key not in seen:
                seen.add(key)
                deduped.append(event)
        return deduped

    def _merge_data_sources(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge and deduplicate data from multiple sources.

        Args:
            data: Raw data from sources

        Returns:
            Merged and deduplicated data
        """
        # Convert Zeek logs to Artemis format and merge with network_connections
        if "zeek_connections" in data and "network_connections" in data:
            zeek_conns = self._convert_zeek_conn(data["zeek_connections"])
            data["network_connections"].extend(zeek_conns)
            del data["zeek_connections"]

        # Merge Zeek DNS with dns_queries
        if "zeek_dns" in data and "dns_queries" in data:
            zeek_dns = self._convert_zeek_dns(data["zeek_dns"])
            data["dns_queries"].extend(zeek_dns)
            del data["zeek_dns"]

        # Merge Zeek HTTP with http_requests
        if "zeek_http" in data:
            zeek_http = self._convert_zeek_http(data["zeek_http"])
            if "http_requests" not in data:
                data["http_requests"] = []
            data["http_requests"].extend(zeek_http)
            del data["zeek_http"]

        # Add Suricata alerts as initial signals
        if "suricata_alerts" in data:
            data["initial_signals"] = self._convert_suricata_alerts(
                data["suricata_alerts"]
            )

        # Deduplicate merged event lists
        conn_keys = ["source_ip", "destination_ip", "destination_port", "timestamp"]
        dns_keys = ["source_ip", "domain", "timestamp"]

        before_conns = len(data.get("network_connections", []))
        before_dns = len(data.get("dns_queries", []))

        if "network_connections" in data:
            data["network_connections"] = self._dedup_events(
                data["network_connections"], conn_keys
            )
        if "dns_queries" in data:
            data["dns_queries"] = self._dedup_events(
                data["dns_queries"], dns_keys
            )

        after_conns = len(data.get("network_connections", []))
        after_dns = len(data.get("dns_queries", []))
        removed = (before_conns - after_conns) + (before_dns - after_dns)
        if removed > 0:
            self.logger.info(
                f"Event dedup: removed {removed} duplicates "
                f"(connections: {before_conns}->{after_conns}, "
                f"dns: {before_dns}->{after_dns})"
            )

        return data

    def _convert_zeek_conn(self, zeek_conns: List[Dict]) -> List[Dict]:
        """Convert Zeek connection logs to Artemis format."""
        converted = []

        for conn in zeek_conns:
            try:
                converted.append({
                    "source_ip": conn.get("id.orig_h"),
                    "destination_ip": conn.get("id.resp_h"),
                    "destination_port": int(conn.get("id.resp_p", 0)),
                    "protocol": conn.get("proto", "tcp"),
                    "bytes_in": int(conn.get("resp_bytes", 0)),
                    "bytes_out": int(conn.get("orig_bytes", 0)),
                    "sensor_id": conn.get("sensor_id", "securityonion"),
                    "vlan": str(conn.get("vlan", "0")),
                    "timestamp": datetime.fromtimestamp(float(conn.get("ts", 0)))
                })
            except:
                continue

        return converted

    def _convert_zeek_dns(self, zeek_dns: List[Dict]) -> List[Dict]:
        """Convert Zeek DNS logs to Artemis format."""
        converted = []

        for dns in zeek_dns:
            try:
                converted.append({
                    "source_ip": dns.get("id.orig_h"),
                    "domain": dns.get("query"),
                    "response_code": dns.get("rcode_name", "NOERROR"),
                    "answer": dns.get("answers"),
                    "sensor_id": dns.get("sensor_id", "securityonion"),
                    "vlan": str(dns.get("vlan", "0")),
                    "timestamp": datetime.fromtimestamp(float(dns.get("ts", 0)))
                })
            except:
                continue

        return converted

    def _convert_zeek_http(self, zeek_http: List[Dict]) -> List[Dict]:
        """Convert Zeek HTTP logs to Artemis format."""
        converted = []

        for http in zeek_http:
            try:
                converted.append({
                    "source_ip": http.get("id.orig_h"),
                    "destination_ip": http.get("id.resp_h"),
                    "method": http.get("method"),
                    "uri": http.get("uri"),
                    "host": http.get("host"),
                    "user_agent": http.get("user_agent"),
                    "timestamp": datetime.fromtimestamp(float(http.get("ts", 0)))
                })
            except:
                continue

        return converted

    def _convert_suricata_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Convert Suricata alerts to initial signals for Artemis."""
        signals = []

        for alert in alerts:
            signals.append({
                "type": "suricata_alert",
                "confidence": 0.6 + (4 - alert.get("severity", 3)) * 0.1,
                "description": alert.get("signature"),
                "category": alert.get("category"),
                "indicators": [alert.get("src_ip"), alert.get("dest_ip")]
            })

        return signals

    def get_context_data(self) -> Dict[str, Any]:
        """
        Get network state context data.

        Returns:
            Context data for NetworkState
        """
        if self.splunk:
            return self.splunk.get_context_data()
        else:
            # Default context
            return {
                "alerts": {
                    "alerts_24h": 0,
                    "alerts_7d": 0,
                    "incident_types": [],
                    "fp_rate": 0.1,
                    "mttd": 300,
                    "mttr": 1800
                },
                "network_traffic": {
                    "bytes_in": 0,
                    "bytes_out": 0,
                    "connections": 0,
                    "unique_destinations": 0,
                    "dns_queries": 0,
                    "failed_connections": 0
                },
                "threat_intelligence": {
                    "campaigns": [],
                    "industry_threats": [],
                    "ioc_matches": 0,
                    "threat_actor_ttps": {},
                    "risk_score": 0.5
                },
                "assets": {
                    "critical_assets": [],
                    "high_value_targets": [],
                    "active_users": 0,
                    "privileged_sessions": 0,
                    "business_critical": []
                }
            }

    def stream_hunting_data(
        self,
        callback,
        time_window: int = 300,
        poll_interval: int = 60
    ):
        """
        Stream hunting data continuously.

        Args:
            callback: Function to call with new data
            time_window: Time window for each batch (seconds)
            poll_interval: How often to poll for new data (seconds)
        """
        import time

        self.logger.info(f"Starting continuous threat hunting stream")

        last_poll = datetime.utcnow()

        while True:
            try:
                # Calculate time range
                now = datetime.utcnow()
                time_range = f"-{time_window}s"

                # Collect data
                hunting_data = self.collect_hunting_data(time_range)

                # Call callback with new data
                callback(hunting_data)

                # Sleep until next poll
                time.sleep(poll_interval)

            except KeyboardInterrupt:
                self.logger.info("Streaming stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Streaming error: {e}")
                time.sleep(poll_interval)
