# Artemis Data Integrations

This module provides connectors for integrating Artemis with real security infrastructure.

## Overview

The integration layer bridges your existing security tools with Artemis hunting agents:

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Infrastructure                       │
├─────────────────┬─────────────────┬─────────────────────────┤
│    Splunk       │ Security Onion  │   PCAP Storage          │
│  (Log Analysis) │ (IDS/NSM)       │ (Terabytes of data)     │
└────────┬────────┴────────┬────────┴────────┬────────────────┘
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│              Artemis Integration Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Splunk     │  │   Security   │  │    PCAP      │      │
│  │  Connector   │  │   Onion      │  │  Analyzer    │      │
│  │              │  │  Connector   │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         └──────────────────┴──────────────────┘              │
│                      Data Pipeline                            │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Artemis Meta-Learner                        │
│                  & Hunting Agents                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. SplunkConnector

Queries Splunk for security events and transforms them into Artemis format.

**Capabilities:**
- Network connection logs
- DNS queries
- Authentication events (Windows, Linux)
- Process execution logs (Sysmon, Windows Event Logs)
- PowerShell script block logging
- File operations
- Scheduled tasks
- Registry modifications
- Context data (alerts, traffic metrics)

**Example:**
```python
from artemis.integrations.splunk_connector import SplunkConnector

splunk = SplunkConnector(
    host="splunk.company.com",
    token="YOUR_TOKEN"
)

# Get all hunting data for last hour
hunting_data = splunk.get_all_hunting_data(time_range="-1h")

# Get specific data types
dns_queries = splunk.get_dns_queries(time_range="-1h")
auth_logs = splunk.get_authentication_logs(time_range="-24h")
process_logs = splunk.get_process_logs(time_range="-1h", hostname_filter="WORKSTATION-01")
```

**SPL Queries Used:**

The connector automatically generates optimized SPL queries:

```spl
# Network connections
search index=network OR index=firewall OR index=zeek
| eval timestamp=_time
| table _time src_ip dest_ip dest_port protocol bytes_in bytes_out

# DNS queries
search index=dns OR sourcetype=bro:dns OR sourcetype=zeek:dns
| table _time src_ip query answer rcode

# Authentication
search index=windows EventCode=4624 OR EventCode=4625
| eval result=if(EventCode=4624, "success", "failure")
| table _time user src_ip dest_host result Logon_Type country

# PowerShell
search index=windows EventCode=4104
| table _time host user ScriptBlockText

# Process execution
search index=windows (EventCode=4688 OR EventCode=1) OR index=sysmon EventCode=1
| table _time host user Process_Name CommandLine ParentProcessName
```

### 2. SecurityOnionConnector

Retrieves PCAPs and Zeek/Suricata logs from Security Onion.

**Capabilities:**
- PCAP retrieval (via Stenographer or direct access)
- Zeek/Bro logs (conn, dns, http, ssl, files, etc.)
- Suricata IDS alerts
- Filtered PCAP extraction by IP, port, or time range

**Example:**
```python
from artemis.integrations.security_onion_connector import SecurityOnionConnector

so = SecurityOnionConnector(
    host="https://securityonion.company.com",
    api_key="YOUR_API_KEY"
)

# Get PCAP for suspicious IP
pcap_path = so.get_pcap_for_ip("10.0.1.50", time_range_hours=1)

# Get Zeek connection logs
zeek_conn = so.get_zeek_logs("conn", time_range_hours=1)

# Get Suricata alerts
alerts = so.get_suricata_alerts(time_range_hours=1, min_severity=1)

# Cleanup temp files
so.cleanup_pcap(pcap_path)
```

### 3. PCAPAnalyzer

Deep packet inspection using Scapy to extract threat hunting features.

**Detections:**
- Port scanning patterns
- C2 beaconing (regular callback intervals)
- Large data transfers (potential exfiltration)
- Suspicious protocol usage (HTTP on weird ports, DNS over TCP)
- DNS queries and responses
- HTTP requests and headers
- Connection flows and statistics

**Example:**
```python
from artemis.integrations.pcap_analyzer import PCAPAnalyzer

analyzer = PCAPAnalyzer()

# Comprehensive analysis
analysis = analyzer.analyze_pcap("/path/to/capture.pcap")

# Results include:
# - network_connections: Flow statistics
# - dns_queries: DNS queries/responses
# - http_requests: HTTP traffic
# - port_scan_indicators: Scanning patterns
# - beaconing_candidates: Potential C2
# - data_transfers: Large transfers
# - suspicious_protocols: Protocol anomalies

# Agent-specific extraction
c2_data = analyzer.extract_for_agent("/path/to/capture.pcap", "c2_hunter")
recon_data = analyzer.extract_for_agent("/path/to/capture.pcap", "reconnaissance_hunter")
```

**PCAP Features Extracted:**

```python
{
    "network_connections": [
        {
            "source_ip": "10.0.1.50",
            "destination_ip": "1.2.3.4",
            "destination_port": 443,
            "protocol": "tcp",
            "packet_count": 150,
            "bytes_transferred": 45000,
            "duration": 60.5
        }
    ],
    "beaconing_candidates": [
        {
            "destination_ip": "1.2.3.4",
            "destination_port": 8080,
            "beacon_count": 25,
            "mean_interval": 60.2,  # seconds
            "regularity": 0.95,      # Low variance = regular beaconing
            "confidence": 0.88
        }
    ],
    "port_scan_indicators": [
        {
            "source_ip": "10.0.1.100",
            "ports_scanned": 1024,
            "scan_type": "SYN scan"
        }
    ]
}
```

### 4. DataPipeline

Orchestrates data collection from all sources with parallel execution.

**Features:**
- Parallel data collection for speed
- Automatic data format conversion (Zeek → Artemis format)
- Deduplication and merging
- Streaming mode for continuous hunting
- Context data aggregation

**Example:**
```python
from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
from artemis import MetaLearnerCoordinator

# Configure data sources
config = DataSourceConfig(
    splunk_host="splunk.company.com",
    splunk_token="TOKEN",
    security_onion_host="https://securityonion.company.com",
    security_onion_api_key="KEY",
    enable_pcap_analysis=True
)

pipeline = DataPipeline(config)
coordinator = MetaLearnerCoordinator()

# Collect data
hunting_data = pipeline.collect_hunting_data(
    time_range="-1h",
    include_pcap=True,
    suspicious_ips=["10.0.1.50", "10.0.1.51"]
)

# Run hunt
assessment = coordinator.hunt(
    data=hunting_data,
    context_data=pipeline.get_context_data()
)

print(f"Confidence: {assessment['final_confidence']:.2f}")
```

**Streaming Mode:**

```python
def hunt_callback(data):
    assessment = coordinator.hunt(data=data)
    if assessment['final_confidence'] >= 0.7:
        alert(assessment)  # Your alerting logic

# Continuous hunting every 5 minutes
pipeline.stream_hunting_data(
    callback=hunt_callback,
    time_window=300,
    poll_interval=60
)
```

## Data Flow

### Typical Hunt Flow

1. **Data Collection** (30-60 seconds)
   - Splunk queries execute in parallel
   - Zeek logs retrieved from Security Onion
   - Suricata alerts fetched
   - Optional: PCAP retrieved and analyzed

2. **Data Transformation** (1-5 seconds)
   - Convert Zeek logs to Artemis format
   - Merge network connections from multiple sources
   - Deduplicate events
   - Generate initial signals from Suricata alerts

3. **Threat Hunting** (5-30 seconds)
   - Meta-learner assesses context
   - Agents selected based on hypotheses
   - Agents analyze data in parallel
   - Findings correlated and confidence aggregated

4. **Results** (< 1 second)
   - Assessment generated
   - Recommendations provided
   - MITRE techniques mapped

**Total Time: ~1-2 minutes for comprehensive hunt**

## Handling Terabytes of Data

### Efficient PCAP Analysis

Your terabytes of PCAP data can be analyzed efficiently:

**1. Targeted Retrieval**
```python
# Don't analyze all data - use BPF filters
pcap = so.get_pcap_for_timerange(
    start_time,
    end_time,
    bpf_filter="host 10.0.1.50 and (port 443 or port 8080)"
)
```

**2. Packet Sampling**
```python
# Analyze first N packets for speed
analysis = analyzer.analyze_pcap(pcap_path, max_packets=50000)
```

**3. On-Demand Analysis**
```python
# Only analyze PCAP when high-confidence detection occurs
if assessment['final_confidence'] >= 0.8:
    # Deep dive with PCAP
    suspicious_ips = extract_ips_from_assessment(assessment)
    pcap_data = pipeline.collect_hunting_data(
        time_range="-1h",
        include_pcap=True,
        suspicious_ips=suspicious_ips
    )
```

**4. Distributed Processing**
```python
# Process PCAPs in chunks across multiple workers
from concurrent.futures import ProcessPoolExecutor

pcap_files = list_pcap_files_in_timerange(start, end)

with ProcessPoolExecutor(max_workers=8) as executor:
    results = executor.map(analyzer.analyze_pcap, pcap_files)
```

### Splunk Performance

**Use Specific Indexes:**
```python
# Don't search all data
query = "search index=network src_ip=10.0.1.50"  # Specific index

# Not this:
query = "search *"  # Searches everything - slow!
```

**Limit Time Ranges:**
```python
# For routine hunts, use short time ranges
hunting_data = pipeline.collect_hunting_data(time_range="-1h")

# For investigations, go deeper
investigation_data = pipeline.collect_hunting_data(time_range="-24h")
```

**Parallel Queries:**
```python
# Pipeline automatically executes queries in parallel
# Collecting 8 data types simultaneously vs sequentially
# Result: 8x faster data collection
```

## Integration Patterns

### Pattern 1: Reactive Hunting
```python
# Triggered by SIEM alert
def handle_siem_alert(alert):
    # Focus hunt on relevant data
    hunting_data = pipeline.collect_hunting_data(
        time_range="-2h",
        suspicious_ips=[alert['source_ip']]
    )

    assessment = coordinator.hunt(data=hunting_data)

    if assessment['final_confidence'] >= 0.7:
        escalate_to_analyst(assessment)
```

### Pattern 2: Proactive Hunting
```python
# Continuous hunting every hour
schedule.every(1).hour.do(lambda: coordinator.hunt(
    data=pipeline.collect_hunting_data("-1h")
))
```

### Pattern 3: Threat Intel Driven
```python
# Hunt based on new IOCs
def hunt_for_ioc(ioc):
    bpf_filter = f"host {ioc}"

    pcap = so.get_pcap_for_timerange(
        datetime.now() - timedelta(days=7),
        datetime.now(),
        bpf_filter=bpf_filter
    )

    if pcap:
        analysis = analyzer.analyze_pcap(pcap)
        # Process analysis...
```

## Performance Benchmarks

### Data Collection Speed
- Splunk (1 hour of data): 15-30 seconds
- Zeek logs (1 hour): 5-10 seconds
- Suricata alerts (1 hour): 2-5 seconds
- PCAP retrieval (10 minutes): 30-60 seconds
- PCAP analysis (50k packets): 10-20 seconds

### Scaling
- 1 hour data: ~1-2 minutes total
- 24 hour data: ~5-10 minutes total
- With PCAP: Add 2-5 minutes per suspicious IP

## Troubleshooting

See `docs/DEPLOYMENT.md` for comprehensive troubleshooting guide.

**Quick fixes:**

```python
# Connection issues
splunk = SplunkConnector(host="...", verify_ssl=False, timeout=120)

# Memory issues with PCAP
analysis = analyzer.analyze_pcap(pcap, max_packets=10000)

# Slow queries
hunting_data = pipeline.collect_hunting_data(time_range="-1h")  # Not -24h
```

## Requirements

```bash
pip install splunk-sdk scapy requests
```

See `requirements.txt` for version details.

## Next Steps

1. Review `examples/production_deployment.py` for complete usage
2. Read `docs/DEPLOYMENT.md` for production deployment guide
3. Configure your data sources in `datasources.json`
4. Start with small time ranges (`-1h`) and scale up
5. Enable adaptive learning for continuous improvement

## Support

- Documentation: See `docs/` directory
- Issues: GitHub issues
- Examples: `examples/` directory
