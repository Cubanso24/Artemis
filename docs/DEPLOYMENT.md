# Artemis Production Deployment Guide

This guide covers deploying Artemis with real security infrastructure (Splunk, Security Onion, PCAP analysis).

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Data Source Integration](#data-source-integration)
5. [Deployment Modes](#deployment-modes)
6. [Performance Tuning](#performance-tuning)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Infrastructure
- **Splunk Enterprise** 8.0+ or Splunk Cloud
  - API access enabled
  - Authentication token or credentials
  - Appropriate indexes configured (network, windows, linux, etc.)

- **Security Onion** 2.3+ (Optional but recommended)
  - PCAP storage configured
  - Zeek/Bro logs enabled
  - Suricata IDS enabled
  - API access or SSH access to sensor

### System Requirements
- **CPU**: 8+ cores recommended
- **RAM**: 16GB+ recommended (32GB for large-scale deployments)
- **Storage**: 100GB+ for logs and temporary PCAP files
- **Network**: 1Gbps+ for handling PCAP analysis

## Installation

### 1. Clone and Install Artemis

```bash
git clone https://github.com/yourusername/artemis.git
cd artemis

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Artemis
pip install -e .
```

### 2. Install Optional Dependencies

```bash
# For enhanced PCAP analysis
pip install pyshark

# For Elasticsearch integration
pip install elasticsearch

# For distributed deployment
pip install redis celery
```

## Configuration

### 1. Basic Configuration

Create `config.json`:

```json
{
  "deployment_mode": "adaptive",
  "enable_parallel_execution": true,
  "max_workers": 4,
  "critical_threshold": 0.9,
  "high_threshold": 0.7,
  "medium_threshold": 0.5,
  "enable_adaptive_learning": true,
  "log_level": "INFO",
  "log_file": "/var/log/artemis/artemis.log"
}
```

### 2. Data Source Configuration

Create `datasources.json`:

```json
{
  "splunk": {
    "host": "splunk.company.com",
    "port": 8089,
    "token": "YOUR_SPLUNK_TOKEN",
    "verify_ssl": true,
    "indexes": {
      "network": "network",
      "windows": "windows",
      "linux": "linux",
      "firewall": "firewall"
    }
  },
  "security_onion": {
    "host": "https://securityonion.company.com",
    "api_key": "YOUR_API_KEY",
    "pcap_storage": "/nsm/pcap",
    "sensors": ["sensor1", "sensor2"]
  },
  "pcap_analysis": {
    "enabled": true,
    "max_packet_count": 100000,
    "temp_storage": "/tmp/artemis/pcap"
  }
}
```

### 3. Environment Variables

Create `.env` file:

```bash
# Splunk
SPLUNK_HOST=splunk.company.com
SPLUNK_TOKEN=your_token_here
SPLUNK_VERIFY_SSL=true

# Security Onion
SECURITY_ONION_HOST=https://securityonion.company.com
SECURITY_ONION_API_KEY=your_api_key

# Artemis
ARTEMIS_LOG_LEVEL=INFO
ARTEMIS_MAX_WORKERS=4
ARTEMIS_DEPLOYMENT_MODE=adaptive
```

## Data Source Integration

### Splunk Integration

#### 1. Create Splunk Service Account

```bash
# In Splunk Web
Settings > Access Controls > Roles > New Role
# Assign capabilities: search, list_search_jobs
```

#### 2. Generate API Token

```bash
# In Splunk Web
Settings > Tokens > New Token
# Save token securely
```

#### 3. Verify Connection

```python
from artemis.integrations.splunk_connector import SplunkConnector

splunk = SplunkConnector(
    host="splunk.company.com",
    token="YOUR_TOKEN"
)

# Test query
results = splunk.query("search index=network | head 10", earliest_time="-1h")
print(f"Retrieved {len(results)} events")
```

### Security Onion Integration

#### 1. Enable API Access (if available)

```bash
# On Security Onion server
sudo so-allow
# Add your management IP
```

#### 2. Configure PCAP Access

```bash
# Ensure PCAP storage is accessible
ls -la /nsm/pcap

# If using SSH for PCAP retrieval
ssh-keygen -t rsa
ssh-copy-id analyst@securityonion
```

#### 3. Verify Zeek Logs

```bash
# Check Zeek logs are being generated
ls -la /nsm/zeek/logs/current/

# Should see: conn.log, dns.log, http.log, ssl.log, etc.
```

### PCAP Analysis Setup

#### 1. Install Scapy System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libpcap-dev

# RHEL/CentOS
sudo yum install python3-devel libpcap-devel

# Verify
python -c "from scapy.all import rdpcap; print('Scapy OK')"
```

#### 2. Configure PCAP Storage

```bash
# Create temp directory for PCAP analysis
sudo mkdir -p /tmp/artemis/pcap
sudo chown artemis:artemis /tmp/artemis/pcap

# Set up log rotation
sudo tee /etc/logrotate.d/artemis-pcap <<EOF
/tmp/artemis/pcap/*.pcap {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

## Deployment Modes

### 1. Single Hunt Mode

Run a one-time threat hunt:

```python
from artemis.examples.production_deployment import run_continuous_hunting

run_continuous_hunting()
```

Or via CLI:

```bash
python -m artemis.examples.production_deployment
```

### 2. Continuous Streaming Mode

Run continuous threat hunting:

```python
from artemis.examples.production_deployment import run_streaming_mode

run_streaming_mode()
```

Or via CLI:

```bash
python -m artemis.examples.production_deployment stream
```

### 3. On-Demand Investigation

Investigate specific host or IP:

```bash
python -m artemis.examples.production_deployment investigate HOSTNAME
```

### 4. Scheduled Hunts (Cron)

Set up scheduled hunts:

```bash
# Edit crontab
crontab -e

# Add hourly hunts
0 * * * * /path/to/artemis/venv/bin/python /path/to/artemis/artemis/examples/production_deployment.py >> /var/log/artemis/cron.log 2>&1

# Add daily comprehensive hunt with PCAP
0 2 * * * /path/to/artemis/scripts/daily_hunt.sh
```

## Performance Tuning

### 1. Splunk Query Optimization

```python
# Use specific indexes
config["splunk"]["indexes"] = {
    "network": "network_prod",
    "windows": "windows_prod"
}

# Limit time ranges
hunting_data = pipeline.collect_hunting_data(
    time_range="-1h"  # Don't go beyond necessary
)

# Use parallel queries
pipeline.splunk.max_concurrent_queries = 8
```

### 2. PCAP Analysis Optimization

```python
# Limit packet count for analysis
pcap_analyzer = PCAPAnalyzer()
analysis = pcap_analyzer.analyze_pcap(
    pcap_path,
    max_packets=50000  # Analyze first 50k packets only
)

# Use BPF filters to reduce PCAP size
pcap_path = security_onion.get_pcap_for_timerange(
    start_time,
    end_time,
    bpf_filter="host 10.0.1.50 and port 443"  # Filter at source
)
```

### 3. Agent Prioritization

```python
# Disable non-critical agents for faster hunts
coordinator.disable_agent("collection_exfiltration_hunter")

# Adjust deployment mode based on urgency
coordinator.set_deployment_mode("sequential")  # Faster than adaptive

# Reduce parallel workers for lower CPU usage
coordinator = MetaLearnerCoordinator(max_workers=2)
```

### 4. Resource Allocation

```python
# Limit memory usage
import resource
resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, -1))  # 4GB limit

# Set process priority
import os
os.nice(10)  # Lower priority to not impact other services
```

## Troubleshooting

### Common Issues

#### 1. Splunk Connection Timeout

```
Error: Connection timeout to Splunk
```

**Solution:**
- Check network connectivity: `ping splunk.company.com`
- Verify Splunk management port: `telnet splunk.company.com 8089`
- Check firewall rules
- Increase timeout in connector:
  ```python
  splunk = SplunkConnector(host="...", timeout=120)
  ```

#### 2. PCAP Analysis Memory Error

```
MemoryError: Cannot allocate memory for PCAP
```

**Solution:**
- Limit packet count: `max_packets=10000`
- Use BPF filters to reduce PCAP size
- Process PCAPs in chunks
- Increase available RAM

#### 3. Security Onion PCAP Not Found

```
FileNotFoundError: PCAP file not found
```

**Solution:**
- Verify PCAP retention policy
- Check PCAP storage path: `/nsm/pcap`
- Ensure time range is within retention
- Check sensor name is correct

#### 4. Slow Threat Hunts

```
Hunt taking > 10 minutes
```

**Solution:**
- Reduce time range: `-1h` instead of `-24h`
- Disable PCAP analysis for routine hunts
- Use `sequential` mode instead of `parallel`
- Reduce `max_workers`
- Optimize Splunk queries (use specific indexes)

### Logging and Debugging

Enable debug logging:

```python
import logging
from artemis.utils.logging_config import ArtemisLogger

logger = ArtemisLogger.setup_logger("artemis", level=logging.DEBUG)
```

Check logs:

```bash
# Artemis logs
tail -f /var/log/artemis/artemis.log

# Splunk connector logs
tail -f /var/log/artemis/artemis.log | grep splunk

# Agent activity
tail -f /var/log/artemis/artemis.log | grep "Agent:"
```

### Performance Monitoring

Monitor Artemis performance:

```python
# Get statistics
stats = coordinator.get_statistics()
print(f"Average hunt time: {stats['average_hunt_time']}")
print(f"Detection rate: {stats['detection_rate']}")

# Get agent metrics
agent_metrics = coordinator.get_agent_metrics()
for agent, metrics in agent_metrics.items():
    print(f"{agent}: {metrics['average_processing_time']:.2f}s")
```

## Best Practices

1. **Start Small**: Begin with 1-hour hunts, then scale to 24-hour
2. **Enable Adaptive Learning**: Provide feedback on detections
3. **Monitor Resource Usage**: Watch CPU, memory, and network
4. **Use Specific Indexes**: Don't query all Splunk data
5. **Schedule Off-Hours**: Run intensive hunts during low-traffic periods
6. **Backup Playbooks**: Regularly export learned playbooks
7. **Test Queries**: Verify Splunk queries return expected data
8. **Rotate Logs**: Set up log rotation for Artemis logs
9. **Alert Integration**: Connect to SIEM/SOAR for automated response
10. **Regular Updates**: Keep Artemis and dependencies updated

## Security Considerations

1. **Credentials**: Store tokens/passwords in secure vault (HashiCorp Vault, AWS Secrets Manager)
2. **Network Segmentation**: Run Artemis in management network
3. **Access Control**: Restrict access to Artemis logs and results
4. **Encryption**: Use TLS for all API connections
5. **Audit Logging**: Log all threat hunting activities
6. **Data Retention**: Follow organizational data retention policies
7. **Least Privilege**: Use minimal required permissions for Splunk/SO

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/artemis/issues
- Documentation: https://artemis-docs.readthedocs.io
- Community: https://discord.gg/artemis-threat-hunting
