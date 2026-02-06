"""
Security Onion connector for PCAP retrieval and analysis.

Integrates with Security Onion to pull packet captures for deep inspection.
"""

import requests
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess
import tempfile
import os

from artemis.utils.logging_config import ArtemisLogger


class SecurityOnionConnector:
    """
    Connector for Security Onion integration.

    Provides PCAP retrieval and analysis capabilities.
    """

    def __init__(
        self,
        host: str,
        api_key: str = "",
        username: str = "",
        password: str = "",
        verify_ssl: bool = True,
        pcap_storage_path: str = "/nsm/pcap"
    ):
        """
        Initialize Security Onion connector.

        Args:
            host: Security Onion server URL
            api_key: API key for authentication (if available)
            username: Username for basic auth
            password: Password for basic auth
            verify_ssl: Whether to verify SSL certificates
            pcap_storage_path: Path to PCAP storage on server
        """
        self.logger = ArtemisLogger.setup_logger("artemis.integrations.securityonion")

        self.host = host.rstrip('/')
        self.api_key = api_key
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.pcap_storage_path = pcap_storage_path

        # Session for API calls
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})
        elif username and password:
            self.session.auth = (username, password)

        self.logger.info(f"Initialized Security Onion connector for {host}")

    def get_pcap_for_timerange(
        self,
        start_time: datetime,
        end_time: datetime,
        bpf_filter: Optional[str] = None,
        sensor: str = "sensor1"
    ) -> str:
        """
        Retrieve PCAP for specified time range.

        Args:
            start_time: Start of capture window
            end_time: End of capture window
            bpf_filter: Optional BPF (Berkeley Packet Filter) for filtering
            sensor: Sensor name

        Returns:
            Path to downloaded PCAP file
        """
        self.logger.info(
            f"Retrieving PCAP from {start_time} to {end_time} "
            f"(filter: {bpf_filter or 'none'})"
        )

        # Create temporary file for PCAP
        temp_pcap = tempfile.NamedTemporaryFile(
            mode='wb',
            suffix='.pcap',
            delete=False
        )

        try:
            # If Security Onion has stenographer, use it
            # Otherwise, use tcpdump on stored PCAPs
            pcap_data = self._extract_pcap_stenographer(
                start_time,
                end_time,
                bpf_filter,
                sensor
            )

            if pcap_data:
                temp_pcap.write(pcap_data)
                temp_pcap.close()
                self.logger.info(f"PCAP saved to {temp_pcap.name}")
                return temp_pcap.name
            else:
                # Fallback: extract from stored PCAPs
                return self._extract_from_stored_pcaps(
                    start_time,
                    end_time,
                    bpf_filter,
                    sensor
                )

        except Exception as e:
            self.logger.error(f"PCAP retrieval failed: {e}")
            temp_pcap.close()
            os.unlink(temp_pcap.name)
            raise

    def _extract_pcap_stenographer(
        self,
        start_time: datetime,
        end_time: datetime,
        bpf_filter: Optional[str],
        sensor: str
    ) -> Optional[bytes]:
        """
        Extract PCAP using Stenographer (if available).

        Args:
            start_time: Start time
            end_time: End time
            bpf_filter: BPF filter
            sensor: Sensor name

        Returns:
            PCAP data or None
        """
        try:
            # Stenographer query format
            query = f"before {end_time.isoformat()} and after {start_time.isoformat()}"
            if bpf_filter:
                query += f" and {bpf_filter}"

            # Call Stenographer API or CLI
            # Example using stenoread command
            cmd = [
                "stenoread",
                "-sensor", sensor,
                "-query", query,
                "-output", "-"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                return result.stdout

        except Exception as e:
            self.logger.debug(f"Stenographer extraction failed: {e}")

        return None

    def _extract_from_stored_pcaps(
        self,
        start_time: datetime,
        end_time: datetime,
        bpf_filter: Optional[str],
        sensor: str
    ) -> str:
        """
        Extract from stored PCAP files using tcpdump.

        Args:
            start_time: Start time
            end_time: End time
            bpf_filter: BPF filter
            sensor: Sensor name

        Returns:
            Path to extracted PCAP
        """
        # Find relevant PCAP files
        pcap_dir = os.path.join(self.pcap_storage_path, sensor)

        # List PCAP files in time range
        # Security Onion typically names PCAPs with timestamps
        pcap_files = []

        try:
            for filename in os.listdir(pcap_dir):
                if filename.endswith('.pcap'):
                    # Extract timestamp from filename (format varies)
                    # Example: snort.log.1234567890
                    try:
                        timestamp_str = filename.split('.')[-2]
                        file_time = datetime.fromtimestamp(int(timestamp_str))

                        if start_time <= file_time <= end_time:
                            pcap_files.append(os.path.join(pcap_dir, filename))
                    except:
                        continue

        except Exception as e:
            self.logger.error(f"Could not list PCAP directory: {e}")
            raise

        if not pcap_files:
            self.logger.warning("No PCAP files found in time range")
            return None

        # Merge and filter PCAPs using tcpdump
        output_pcap = tempfile.NamedTemporaryFile(
            mode='wb',
            suffix='.pcap',
            delete=False
        ).name

        # Build tcpdump command
        cmd = ["tcpdump", "-r"]
        cmd.extend(pcap_files)
        cmd.extend(["-w", output_pcap])

        if bpf_filter:
            cmd.append(bpf_filter)

        try:
            subprocess.run(cmd, check=True, timeout=600)
            self.logger.info(f"Merged {len(pcap_files)} PCAP files")
            return output_pcap
        except Exception as e:
            self.logger.error(f"PCAP merging failed: {e}")
            raise

    def get_pcap_for_ip(
        self,
        ip_address: str,
        time_range_hours: int = 1,
        direction: str = "both"
    ) -> str:
        """
        Get PCAP for specific IP address.

        Args:
            ip_address: IP address to filter
            time_range_hours: Hours of history to retrieve
            direction: "src", "dst", or "both"

        Returns:
            Path to PCAP file
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        # Build BPF filter
        if direction == "src":
            bpf_filter = f"src host {ip_address}"
        elif direction == "dst":
            bpf_filter = f"dst host {ip_address}"
        else:  # both
            bpf_filter = f"host {ip_address}"

        return self.get_pcap_for_timerange(
            start_time,
            end_time,
            bpf_filter
        )

    def get_pcap_for_port(
        self,
        port: int,
        protocol: str = "tcp",
        time_range_hours: int = 1
    ) -> str:
        """
        Get PCAP for specific port.

        Args:
            port: Port number
            protocol: "tcp" or "udp"
            time_range_hours: Hours of history

        Returns:
            Path to PCAP file
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        bpf_filter = f"{protocol} port {port}"

        return self.get_pcap_for_timerange(
            start_time,
            end_time,
            bpf_filter
        )

    def get_zeek_logs(
        self,
        log_type: str = "conn",
        time_range_hours: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Get Zeek/Bro logs from Security Onion.

        Args:
            log_type: Type of Zeek log (conn, dns, http, ssl, etc.)
            time_range_hours: Hours of history

        Returns:
            List of Zeek log entries
        """
        # Zeek logs are typically in /nsm/zeek/logs
        zeek_log_path = f"/nsm/zeek/logs/current/{log_type}.log"

        try:
            # Read Zeek log (TSV format)
            logs = []

            with open(zeek_log_path, 'r') as f:
                headers = None

                for line in f:
                    if line.startswith('#'):
                        # Parse header
                        if line.startswith('#fields'):
                            headers = line.split('\t')[1:]
                            headers = [h.strip() for h in headers]
                        continue

                    if headers:
                        values = line.strip().split('\t')
                        log_entry = dict(zip(headers, values))
                        logs.append(log_entry)

            self.logger.info(f"Retrieved {len(logs)} {log_type} logs from Zeek")
            return logs

        except Exception as e:
            self.logger.error(f"Failed to read Zeek logs: {e}")
            return []

    def get_suricata_alerts(
        self,
        time_range_hours: int = 1,
        min_severity: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Get Suricata IDS alerts.

        Args:
            time_range_hours: Hours of history
            min_severity: Minimum severity (1=high, 3=low)

        Returns:
            List of Suricata alerts
        """
        # Suricata logs are typically in EVE JSON format
        eve_log_path = "/nsm/suricata/eve.json"

        try:
            alerts = []
            cutoff_time = datetime.utcnow() - timedelta(hours=time_range_hours)

            with open(eve_log_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)

                        if event.get('event_type') == 'alert':
                            # Parse timestamp
                            event_time = datetime.fromisoformat(
                                event.get('timestamp', '').replace('Z', '+00:00')
                            )

                            if event_time >= cutoff_time:
                                alert = event.get('alert', {})
                                severity = alert.get('severity', 3)

                                if severity <= min_severity:
                                    alerts.append({
                                        'timestamp': event_time,
                                        'signature': alert.get('signature'),
                                        'category': alert.get('category'),
                                        'severity': severity,
                                        'src_ip': event.get('src_ip'),
                                        'dest_ip': event.get('dest_ip'),
                                        'src_port': event.get('src_port'),
                                        'dest_port': event.get('dest_port'),
                                        'protocol': event.get('proto')
                                    })
                    except:
                        continue

            self.logger.info(f"Retrieved {len(alerts)} Suricata alerts")
            return alerts

        except Exception as e:
            self.logger.error(f"Failed to read Suricata alerts: {e}")
            return []

    def cleanup_pcap(self, pcap_path: str):
        """
        Clean up temporary PCAP file.

        Args:
            pcap_path: Path to PCAP file to delete
        """
        try:
            if os.path.exists(pcap_path):
                os.unlink(pcap_path)
                self.logger.debug(f"Cleaned up PCAP: {pcap_path}")
        except Exception as e:
            self.logger.warning(f"Failed to cleanup PCAP {pcap_path}: {e}")
