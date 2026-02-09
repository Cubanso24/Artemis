"""
Splunk connector for querying security logs.

Integrates with Splunk to pull data for Artemis agents.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import concurrent.futures

try:
    import splunklib.client as client
    import splunklib.results as results
    SPLUNK_AVAILABLE = True
except ImportError:
    SPLUNK_AVAILABLE = False

from artemis.utils.logging_config import ArtemisLogger


def parse_splunk_timestamp(time_value: Any) -> datetime:
    """
    Parse Splunk timestamp which can be in multiple formats.

    Args:
        time_value: Timestamp from Splunk (epoch float or ISO string)

    Returns:
        datetime object
    """
    if not time_value:
        return datetime.utcnow()

    try:
        # Try parsing as epoch timestamp (float)
        return datetime.fromtimestamp(float(time_value))
    except (ValueError, TypeError):
        pass

    try:
        # Try parsing as ISO format string
        # Handle format like '2026-02-06T17:10:58.936+00:00'
        time_str = str(time_value)

        # Remove timezone suffix for parsing
        if '+' in time_str:
            time_str = time_str.split('+')[0]
        elif time_str.endswith('Z'):
            time_str = time_str[:-1]

        # Parse the timestamp
        return datetime.fromisoformat(time_str)
    except (ValueError, TypeError):
        pass

    # Fallback to current time
    return datetime.utcnow()


class SplunkConnector:
    """
    Connector for Splunk SIEM integration.

    Queries Splunk for security logs and transforms them into
    the format expected by Artemis hunting agents.
    """

    def __init__(
        self,
        host: str,
        port: int = 8089,
        username: str = "",
        password: str = "",
        token: Optional[str] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize Splunk connector.

        Args:
            host: Splunk server hostname/IP
            port: Splunk management port (default 8089)
            username: Splunk username (if using basic auth)
            password: Splunk password (if using basic auth)
            token: Splunk authentication token (preferred)
            verify_ssl: Whether to verify SSL certificates
        """
        if not SPLUNK_AVAILABLE:
            raise ImportError(
                "splunk-sdk is not installed. "
                "Install with: pip install splunk-sdk"
            )

        self.logger = ArtemisLogger.setup_logger("artemis.integrations.splunk")

        # Connect to Splunk
        if token:
            self.service = client.connect(
                host=host,
                port=port,
                token=token,
                verify=verify_ssl
            )
        else:
            self.service = client.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                verify=verify_ssl
            )

        self.logger.info(f"Connected to Splunk at {host}:{port}")

    def query(
        self,
        search_query: str,
        earliest_time: str = "-1h",
        latest_time: str = "now",
        max_results: int = 0  # 0 = unlimited, get ALL results
    ) -> List[Dict[str, Any]]:
        """
        Execute Splunk search query.

        Args:
            search_query: SPL (Splunk Processing Language) query
            earliest_time: Start time (e.g., "-1h", "-24h", "2024-01-01T00:00:00")
            latest_time: End time (default "now")
            max_results: Maximum results to return (0 = unlimited)

        Returns:
            List of events as dictionaries
        """
        self.logger.info(f"Executing Splunk query: {search_query[:100]}...")

        # Create search job - don't limit results in job creation
        kwargs = {
            "earliest_time": earliest_time,
            "latest_time": latest_time
        }

        # Only add max_count if it's not 0 (unlimited)
        if max_results > 0:
            kwargs["max_count"] = max_results

        job = self.service.jobs.create(search_query, **kwargs)

        # Wait for job to complete with timeout
        import time
        start_time = time.time()
        timeout = 600  # 10 minute timeout per job

        while not job.is_done():
            if time.time() - start_time > timeout:
                self.logger.error(f"Query timed out after {timeout} seconds")
                raise TimeoutError(f"Splunk query exceeded {timeout} second timeout")
            time.sleep(0.5)

        self.logger.info(f"Job completed in {time.time() - start_time:.1f} seconds, retrieving results...")

        # Get result count to determine pagination strategy
        result_count = int(job["resultCount"])
        self.logger.info(f"Job has {result_count} total results")

        if result_count == 0:
            return []

        # Determine how many results to actually fetch
        fetch_count = result_count if max_results == 0 else min(result_count, max_results)

        # Calculate pages needed
        page_size = 50000
        num_pages = (fetch_count + page_size - 1) // page_size  # Ceiling division

        self.logger.info(f"Fetching {fetch_count} events in {num_pages} pages using SEQUENTIAL pagination (debugging)")

        # Fetch pages sequentially with detailed logging
        events = []
        for page_num in range(num_pages):
            offset = page_num * page_size
            count = min(page_size, fetch_count - offset)

            self.logger.info(f"Fetching page {page_num + 1}/{num_pages} (offset={offset}, count={count})...")

            try:
                result_kwargs = {"offset": offset, "count": count}
                page_results = list(results.ResultsReader(job.results(**result_kwargs)))

                # Filter out non-dict results (like messages)
                page_events = [r for r in page_results if isinstance(r, dict)]

                events.extend(page_events)
                self.logger.info(f"Retrieved page {page_num + 1}/{num_pages}: {len(page_events)} events (total so far: {len(events)})")

                # If we got fewer events than expected, something is wrong
                if len(page_events) == 0 and page_num < num_pages - 1:
                    self.logger.warning(f"Page {page_num + 1} returned 0 events but more pages expected - stopping pagination")
                    break

            except Exception as e:
                self.logger.error(f"Failed to fetch page {page_num + 1}: {str(e)}")
                import traceback
                self.logger.error(f"Traceback: {traceback.format_exc()}")
                break

        self.logger.info(f"Retrieved {len(events)} total events from Splunk (expected {fetch_count})")
        return events

    def get_network_connections(
        self,
        time_range: str = "-1h",
        source_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get network connection data for reconnaissance/C2 detection.

        Args:
            time_range: Time range (e.g., "-1h", "-24h")
            source_filter: Optional filter for source IPs

        Returns:
            Network connections in Artemis format
        """
        # Use Zeek field names: id.orig_h, id.resp_h, id.resp_p, orig_bytes, resp_bytes
        # spath extracts JSON fields from _raw
        query = '''
        search index=zeek_conn OR index=suricata
        | spath
        | eval timestamp=_time
        | table _time id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes conn_state
        | rename "id.orig_h" as source_ip, "id.resp_h" as destination_ip, "id.resp_p" as destination_port, proto as protocol, orig_bytes as bytes_in, resp_bytes as bytes_out
        '''

        if source_filter:
            query += f' | where source_ip="{source_filter}"'

        events = self.query(query, earliest_time=time_range)

        # Transform to Artemis format
        # Note: spath returns multi-valued fields as lists, so we take first element
        connections = []
        for event in events:
            # Helper to extract first value from list or return the value
            def get_first(value, default=""):
                if isinstance(value, list) and len(value) > 0:
                    return value[0]
                return value if value else default

            connections.append({
                "source_ip": get_first(event.get("source_ip")),
                "destination_ip": get_first(event.get("destination_ip")),
                "destination_port": int(get_first(event.get("destination_port"), 0)),
                "protocol": get_first(event.get("protocol"), "tcp"),
                "bytes_in": int(get_first(event.get("bytes_in"), 0)),
                "bytes_out": int(get_first(event.get("bytes_out"), 0)),
                "conn_state": get_first(event.get("conn_state"), ""),
                "timestamp": parse_splunk_timestamp(get_first(event.get("_time")))
            })

        return connections

    def get_dns_queries(self, time_range: str = "-1h") -> List[Dict[str, Any]]:
        """
        Get DNS query data for reconnaissance/C2 detection.

        Returns:
            DNS queries in Artemis format
        """
        # Use Zeek DNS field names: id.orig_h, query, rcode_name
        # spath extracts JSON fields from _raw
        # Note: Zeek DNS doesn't always have 'answers' field, so we omit it
        query = '''
        search index=zeek_dns
        | spath
        | table _time id.orig_h query rcode_name
        | rename "id.orig_h" as source_ip, rcode_name as response_code
        '''

        events = self.query(query, earliest_time=time_range)

        # Note: spath returns multi-valued fields as lists, so we take first element
        dns_queries = []
        for event in events:
            # Helper to extract first value from list or return the value
            def get_first(value, default=""):
                if isinstance(value, list) and len(value) > 0:
                    return value[0]
                return value if value else default

            dns_queries.append({
                "source_ip": get_first(event.get("source_ip")),
                "domain": get_first(event.get("query")),
                "response_code": get_first(event.get("response_code"), "NOERROR"),
                "timestamp": parse_splunk_timestamp(get_first(event.get("_time")))
            })

        return dns_queries

    def get_authentication_logs(self, time_range: str = "-1h") -> List[Dict[str, Any]]:
        """
        Get authentication logs for credential access/initial access detection.

        Returns:
            Authentication events in Artemis format
        """
        query = '''
        search index=security_win EventCode=4624 OR EventCode=4625
        | eval result=if(EventCode=4624, "success", "failure")
        | table _time user src_ip dest_host result Logon_Type country
        | rename user as username, src_ip as source_ip, dest_host as target_hostname
        '''

        events = self.query(query, earliest_time=time_range)

        auth_logs = []
        for event in events:
            auth_logs.append({
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "target_hostname": event.get("target_hostname"),
                "result": event.get("result", "unknown"),
                "logon_type": event.get("Logon_Type"),
                "country": event.get("country"),
                "timestamp": parse_splunk_timestamp(event.get("_time"))
            })

        return auth_logs

    def get_process_logs(
        self,
        time_range: str = "-1h",
        hostname_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get process execution logs for execution/persistence detection.

        Returns:
            Process events in Artemis format
        """
        query = '''
        search index=sysmon_win EventCode=1 OR index=security_win EventCode=4688
        | table _time host user Process_Name CommandLine ParentProcessName ParentCommandLine
        | rename host as hostname, user as user, Process_Name as process_name,
                 CommandLine as command_line, ParentProcessName as parent_process
        '''

        if hostname_filter:
            query += f' | where hostname="{hostname_filter}"'

        events = self.query(query, earliest_time=time_range)

        process_logs = []
        for event in events:
            process_logs.append({
                "hostname": event.get("hostname"),
                "user": event.get("user"),
                "process_name": event.get("process_name"),
                "command_line": event.get("command_line", ""),
                "parent_process": event.get("parent_process"),
                "timestamp": parse_splunk_timestamp(event.get("_time"))
            })

        return process_logs

    def get_powershell_logs(self, time_range: str = "-1h") -> List[Dict[str, Any]]:
        """
        Get PowerShell execution logs.

        Returns:
            PowerShell events in Artemis format
        """
        query = '''
        search index=powershell_win EventCode=4104
        | table _time host user ScriptBlockText Message
        | rename host as hostname, ScriptBlockText as command_line
        | eval command_line=coalesce(command_line, Message)
        '''

        events = self.query(query, earliest_time=time_range)

        ps_logs = []
        for event in events:
            ps_logs.append({
                "hostname": event.get("hostname"),
                "user": event.get("user"),
                "command_line": event.get("command_line", ""),
                "timestamp": parse_splunk_timestamp(event.get("_time"))
            })

        return ps_logs

    def get_file_operations(self, time_range: str = "-1h") -> List[Dict[str, Any]]:
        """
        Get file operation logs for collection/impact detection.

        Returns:
            File operations in Artemis format
        """
        query = '''
        search index=security_win EventCode=4663 OR index=sysmon_win EventCode=11
        | table _time host user Object_Name Access_Mask TargetFilename
        | rename host as hostname, Object_Name as filename, TargetFilename as filename
        | eval operation=case(
            match(Access_Mask, "DELETE"), "delete",
            match(Access_Mask, "WRITE"), "modify",
            1=1, "access"
          )
        '''

        events = self.query(query, earliest_time=time_range)

        file_ops = []
        for event in events:
            file_ops.append({
                "hostname": event.get("hostname"),
                "user": event.get("user"),
                "filename": event.get("filename"),
                "operation": event.get("operation", "access"),
                "timestamp": parse_splunk_timestamp(event.get("_time"))
            })

        return file_ops

    def get_scheduled_tasks(self, time_range: str = "-1h") -> List[Dict[str, Any]]:
        """
        Get scheduled task creation events.

        Returns:
            Scheduled tasks in Artemis format
        """
        query = '''
        search index=security_win EventCode=4698
        | table _time host user TaskName TaskContent
        | rename host as hostname, TaskName as task_name, TaskContent as command
        | eval event_type="created"
        '''

        events = self.query(query, earliest_time=time_range)

        tasks = []
        for event in events:
            tasks.append({
                "hostname": event.get("hostname"),
                "task_name": event.get("task_name"),
                "command": event.get("command", ""),
                "event_type": event.get("event_type"),
                "creator": event.get("user"),
                "timestamp": parse_splunk_timestamp(event.get("_time"))
            })

        return tasks

    def get_registry_changes(self, time_range: str = "-1h") -> List[Dict[str, Any]]:
        """
        Get registry modification events.

        Returns:
            Registry changes in Artemis format
        """
        query = '''
        search index=security_win EventCode=4657 OR index=sysmon_win EventCode=13
        | table _time host user Object_Name Details TargetObject
        | rename host as hostname, Object_Name as key_path, TargetObject as key_path,
                 Details as value_data
        '''

        events = self.query(query, earliest_time=time_range)

        reg_changes = []
        for event in events:
            key_path = event.get("key_path", "")
            value_name = key_path.split("\\")[-1] if "\\" in key_path else ""

            reg_changes.append({
                "hostname": event.get("hostname"),
                "user": event.get("user"),
                "key_path": key_path,
                "value_name": value_name,
                "value_data": event.get("value_data", ""),
                "timestamp": parse_splunk_timestamp(event.get("_time"))
            })

        return reg_changes

    def get_all_hunting_data(self, time_range: str = "-1h") -> Dict[str, List]:
        """
        Get comprehensive hunting data for all Artemis agents.

        Args:
            time_range: Time range for data collection

        Returns:
            Dictionary with all data types
        """
        self.logger.info(f"Collecting comprehensive hunting data for {time_range}")

        hunting_data = {
            "network_connections": self.get_network_connections(time_range),
            "dns_queries": self.get_dns_queries(time_range),
            "authentication_logs": self.get_authentication_logs(time_range),
            "process_logs": self.get_process_logs(time_range),
            "powershell_logs": self.get_powershell_logs(time_range),
            "file_operations": self.get_file_operations(time_range),
            "scheduled_tasks": self.get_scheduled_tasks(time_range),
            "registry_changes": self.get_registry_changes(time_range)
        }

        total_events = sum(len(v) for v in hunting_data.values())
        self.logger.info(f"Collected {total_events} total events from Splunk")

        return hunting_data

    def get_context_data(self) -> Dict[str, Any]:
        """
        Get network state context data from Splunk.

        Returns:
            Context data for NetworkState
        """
        # Get last 24 hours of alerts
        alert_query = '''
        search index=notable OR index=alerts earliest=-24h
        | stats count as alerts_24h
        '''

        # Get last 7 days of alerts
        alert_query_7d = '''
        search index=notable OR index=alerts earliest=-7d
        | stats count as alerts_7d
        '''

        # Get traffic metrics
        traffic_query = '''
        search index=network earliest=-1h
        | stats sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out,
                dc(dest_ip) as unique_destinations, count as connections
        '''

        alerts_24h = self.query(alert_query)
        alerts_7d = self.query(alert_query_7d)
        traffic = self.query(traffic_query)

        context = {
            "alerts": {
                "alerts_24h": int(alerts_24h[0].get("alerts_24h", 0)) if alerts_24h else 0,
                "alerts_7d": int(alerts_7d[0].get("alerts_7d", 0)) if alerts_7d else 0,
                "incident_types": [],
                "fp_rate": 0.1,  # Would calculate from historical data
                "mttd": 300,
                "mttr": 1800
            },
            "network_traffic": {
                "bytes_in": int(traffic[0].get("bytes_in", 0)) if traffic else 0,
                "bytes_out": int(traffic[0].get("bytes_out", 0)) if traffic else 0,
                "connections": int(traffic[0].get("connections", 0)) if traffic else 0,
                "unique_destinations": int(traffic[0].get("unique_destinations", 0)) if traffic else 0,
                "dns_queries": 0,  # Would query separately
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
                "active_users": 100,  # Would query from authentication logs
                "privileged_sessions": 5,
                "business_critical": []
            }
        }

        return context
