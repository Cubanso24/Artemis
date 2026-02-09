"""
Data pipeline for orchestrating data collection from multiple sources.

Coordinates Splunk, Security Onion, and PCAP analysis to provide
comprehensive data to Artemis hunting agents.
"""

from typing import Dict, List, Any, Optional
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
        suspicious_ips: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Collect comprehensive hunting data from all sources.

        Args:
            time_range: Time range for data collection (e.g., "-1h", "-24h")
            include_pcap: Whether to retrieve and analyze PCAP
            suspicious_ips: Optional list of IPs to focus on

        Returns:
            Comprehensive hunting data dictionary
        """
        self.logger.info(f"Collecting hunting data for time range: {time_range}")

        hunting_data = {}

        # Collect from Splunk (if available)
        if self.splunk:
            splunk_data = self._collect_from_splunk(time_range)
            hunting_data.update(splunk_data)

        # Collect from Security Onion
        if self.security_onion:
            so_data = self._collect_from_security_onion(
                time_range,
                include_pcap,
                suspicious_ips
            )
            hunting_data.update(so_data)

        # Merge and deduplicate
        hunting_data = self._merge_data_sources(hunting_data)

        total_events = sum(
            len(v) if isinstance(v, list) else 0
            for v in hunting_data.values()
        )
        self.logger.info(f"Collected {total_events} total events")

        return hunting_data

    def _collect_from_splunk(self, time_range: str) -> Dict[str, Any]:
        """
        Collect data from Splunk.

        Args:
            time_range: Time range for queries

        Returns:
            Splunk data dictionary
        """
        self.logger.info("Collecting data from Splunk...")

        data = {}

        try:
            # Use parallel execution for faster collection - maximize CPU utilization
            # Each data type query runs in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                futures = {
                    "network_connections": executor.submit(
                        self.splunk.get_network_connections, time_range
                    ),
                    "dns_queries": executor.submit(
                        self.splunk.get_dns_queries, time_range
                    ),
                    "authentication_logs": executor.submit(
                        self.splunk.get_authentication_logs, time_range
                    ),
                    "process_logs": executor.submit(
                        self.splunk.get_process_logs, time_range
                    ),
                    "powershell_logs": executor.submit(
                        self.splunk.get_powershell_logs, time_range
                    ),
                    "file_operations": executor.submit(
                        self.splunk.get_file_operations, time_range
                    ),
                    "scheduled_tasks": executor.submit(
                        self.splunk.get_scheduled_tasks, time_range
                    ),
                    "registry_changes": executor.submit(
                        self.splunk.get_registry_changes, time_range
                    )
                }

                # Collect results - increased timeout for large datasets
                for key, future in futures.items():
                    try:
                        data[key] = future.result(timeout=600)  # 10 minutes for millions of events
                    except Exception as e:
                        import traceback
                        error_msg = f"Failed to collect {key}: {str(e)}"
                        self.logger.error(error_msg)
                        self.logger.error(f"Traceback: {traceback.format_exc()}")
                        data[key] = []

        except Exception as e:
            self.logger.error(f"Splunk data collection failed: {e}")

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
