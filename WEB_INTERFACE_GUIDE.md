# Artemis Web Interface Guide

## Overview

The Artemis Web Interface provides a modern, user-friendly way to:
- Start and monitor threat hunts in real-time
- View historical hunt results
- Manage plugins and extensions
- Visualize network activity
- Track system performance

**Key Benefits:**
- ✅ **No restarts required** - Long-running service
- ✅ **Real-time progress** - WebSocket updates during hunts
- ✅ **Persistent storage** - SQLite database for all results
- ✅ **Extensible** - Plugin architecture for new capabilities
- ✅ **REST API** - Automate everything programmatically

---

## Quick Start

### 1. Install Dependencies

```bash
cd ~/Artemis
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set Splunk Credentials

```bash
export SPLUNK_TOKEN="your-token-here"
# OR
export SPLUNK_USERNAME="admin"
export SPLUNK_PASSWORD="your-password"
```

### 3. Start Artemis Server

```bash
./start_artemis.sh
# OR
python artemis_server.py
```

### 4. Open Web UI

Navigate to: **http://localhost:8000**

---

## Web Interface Tour

### Dashboard Tab

**Quick Actions:**
- **Hunt Last Hour** → Immediate 1-hour hunt
- **Hunt Last 24 Hours** → Full day analysis
- **Hunt Last Week** → Weekly comprehensive sweep

**Recent Hunts:**
- See the 5 most recent hunts
- Click any hunt to view detailed results
- Status indicators (Running, Completed, Failed)

### New Hunt Tab

**Configure Custom Hunts:**

1. **Time Range** → Select data timeframe
   - Last Hour → Real-time threats
   - Last 24 Hours → Daily sweep
   - Last 7/30 Days → Historical analysis

2. **Hunt Mode:**
   - **Parallel** (Recommended) → All agents at once, fastest
   - **Adaptive** → Progressive deployment based on findings
   - **Sequential** → One agent at a time, most thorough

3. **Description** → Optional notes for tracking

**Real-Time Progress:**
- Progress bar shows hunt stages
- Live updates via WebSocket
- Stages: Init → Collect → Analyze → Hunt → Finalize

### Hunt History Tab

**View All Past Hunts:**
- Sortable list of all hunts
- Click to see detailed findings
- Filter by status, time range, confidence

**Hunt Details:**
- Total findings count
- Overall confidence score
- MITRE ATT&CK mapping
- Affected assets
- Findings grouped by severity

### Plugins Tab

**Manage Extensions:**
- View available plugins
- Enable/disable without restart
- Configure plugin settings
- See plugin status

**Built-in Plugins:**
- **Network Mapper** → Build topology maps

### Live Logs Tab

**Real-Time System Logs:**
- See what Artemis is doing
- Color-coded by severity (Info, Warning, Error)
- Automatically scrolls to latest
- Keeps last 100 log entries

---

## Using the Network Mapper Plugin

### What It Does

The Network Mapper plugin automatically builds a network topology map from observed traffic:

- **Discovers hosts** (internal and external)
- **Identifies services** (ports and protocols)
- **Tracks connections** (who talks to whom)
- **Infers roles** (servers, clients, scanners)
- **Links hostnames** (from DNS queries)

### Enabling the Plugin

1. Go to **Plugins** tab
2. Find "Network Mapper"
3. Click **Enable**

### How It Works

**Automatically processes hunt data:**
- Every time you run a hunt, network mapper processes the connections
- Builds cumulative map over time
- Auto-saves every 5 minutes

**Output Files** (in `network_maps/` directory):
- `current_map.json` → Full network graph data
- `network_summary.txt` → Human-readable summary

### Viewing the Network Map

**Summary Report:**
```bash
cat network_maps/network_summary.txt
```

Shows:
- Total nodes (internal/external)
- Top internal hosts by activity
- Top external destinations
- Identified servers and services

**JSON Data:**
```bash
cat network_maps/current_map.json
```

Contains:
- All nodes with metadata
- Connection counts
- Service lists
- Role assignments

### Example Output

```
TOP INTERNAL HOSTS (by connection count):
  10.0.1.50      |   4523 conns | Roles: client
                   Services: 443/tcp, 80/tcp
  10.0.1.75      |   2341 conns | Roles: server, web_server
                   Services: 443/tcp, 80/tcp, 8080/tcp

IDENTIFIED SERVERS (12):
  10.0.1.100     | Services: 53/udp, 53/tcp (DNS Server)
  10.0.1.101     | Services: 80/tcp, 443/tcp (Web Server)
  10.0.1.102     | Services: 25/tcp, 587/tcp (Mail Server)
```

---

## REST API Usage

All web UI functions are available via REST API for automation.

### API Documentation

Interactive API docs: **http://localhost:8000/docs**

### Common API Endpoints

**Get Server Status:**
```bash
curl http://localhost:8000/api/status
```

**Start a Hunt:**
```bash
curl -X POST http://localhost:8000/api/hunt \
  -H "Content-Type: application/json" \
  -d '{"time_range": "-1h", "mode": "PARALLEL", "description": "Automated hourly hunt"}'
```

**List Recent Hunts:**
```bash
curl http://localhost:8000/api/hunts?limit=50
```

**Get Hunt Details:**
```bash
curl http://localhost:8000/api/hunts/hunt_20260209_120000
```

**List Plugins:**
```bash
curl http://localhost:8000/api/plugins
```

**Enable Plugin:**
```bash
curl -X POST http://localhost:8000/api/plugins/network_mapper/enable \
  -H "Content-Type: application/json" \
  -d '{"name": "network_mapper", "enabled": true, "config": {}}'
```

### Automation Examples

**Hourly Hunt via Cron:**
```bash
# Add to crontab:
0 * * * * curl -X POST http://localhost:8000/api/hunt -H "Content-Type: application/json" -d '{"time_range": "-1h", "mode": "PARALLEL"}'
```

**Hunt on Alert from SIEM:**
```bash
#!/bin/bash
# Called by SIEM when alert triggers

HUNT_ID=$(curl -s -X POST http://localhost:8000/api/hunt \
  -H "Content-Type: application/json" \
  -d '{"time_range": "-4h", "mode": "ADAPTIVE", "description": "SIEM alert investigation"}' \
  | jq -r '.hunt_id')

echo "Started hunt: $HUNT_ID"
```

---

## Running as a Service

### Systemd Service (Recommended)

**1. Edit service file:**
```bash
vim artemis.service
```

Update `SPLUNK_TOKEN` with your actual token.

**2. Install service:**
```bash
sudo cp artemis.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable artemis
sudo systemctl start artemis
```

**3. Check status:**
```bash
sudo systemctl status artemis
```

**4. View logs:**
```bash
sudo journalctl -u artemis -f
```

### Manual Background Mode

```bash
nohup ./start_artemis.sh > artemis.log 2>&1 &
```

---

## Creating Custom Plugins

### Plugin Structure

```python
from artemis.plugins import ArtemisPlugin

class MyCustomPlugin(ArtemisPlugin):
    """My custom plugin description."""

    DESCRIPTION = "Does something awesome"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Initialize your plugin

    def initialize(self):
        """Called when plugin is enabled."""
        self.enabled = True
        # Setup resources

    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Called to run plugin functionality.

        kwargs may include:
          - network_connections: List of connections
          - dns_queries: List of DNS queries
          - findings: Current hunt findings
        """
        # Do your processing
        return {'status': 'success', 'data': {}}

    def cleanup(self):
        """Called when plugin is disabled."""
        # Clean up resources
        self.enabled = False
```

### Registering Your Plugin

In `artemis_server.py`:

```python
from artemis.plugins.my_custom_plugin import MyCustomPlugin
plugin_manager.register_plugin('my_custom', MyCustomPlugin)
```

**No restart needed!** Plugin available immediately.

### Plugin Ideas

**1. Geo-Location Tracker:**
- Map external IPs to geographic locations
- Identify connections to high-risk countries
- Alert on unexpected geographic patterns

**2. Threat Intel Enrichment:**
- Query threat intel feeds for IPs/domains
- Enrich findings with reputation data
- Tag known-bad indicators

**3. Automated Response:**
- Block malicious IPs in firewall
- Quarantine infected hosts
- Trigger SOAR playbooks

**4. Slack/Teams Alerting:**
- Send high-confidence findings to chat
- Create tickets in Jira/ServiceNow
- Email security team

**5. Traffic Baseline Analyzer:**
- Track normal traffic patterns
- Detect statistical anomalies
- Alert on deviations

**6. Attack Path Visualizer:**
- Show lateral movement chains
- Visualize kill chain progression
- Identify patient zero

---

## Database Structure

Artemis uses SQLite for persistent storage.

**Database:** `artemis.db`

**Tables:**

1. **hunts** - Hunt metadata
   - hunt_id, start_time, end_time
   - time_range, mode, status
   - total_findings, overall_confidence

2. **findings** - Individual findings
   - hunt_id, agent_name, title
   - description, severity, confidence
   - mitre_tactics, affected_assets

3. **plugin_results** - Plugin output
   - plugin_name, timestamp
   - result_type, result_data

### Querying the Database

```bash
sqlite3 artemis.db

# Get hunt statistics
SELECT mode, COUNT(*) as hunts, AVG(total_findings) as avg_findings
FROM hunts
GROUP BY mode;

# Find high-confidence findings
SELECT hunt_id, agent_name, title, confidence
FROM findings
WHERE confidence > 0.8
ORDER BY confidence DESC
LIMIT 20;

# Top agents by findings
SELECT agent_name, COUNT(*) as finding_count
FROM findings
GROUP BY agent_name
ORDER BY finding_count DESC;
```

---

## Performance Tuning

### Optimize for Large Hunts

**Adjust worker threads:**
```python
# In artemis_server.py
self.executor = ThreadPoolExecutor(max_workers=8)  # Increase from 4
```

**Limit data collection:**
```python
# In hunt request
{"time_range": "-1h", "mode": "PARALLEL", "sample_rate": 0.5}
```

**Use database indexing:**
```sql
CREATE INDEX idx_findings_confidence ON findings(confidence DESC);
CREATE INDEX idx_hunts_status ON hunts(status);
```

### Monitor Resource Usage

```bash
# CPU and memory
htop

# Database size
ls -lh artemis.db

# Active connections
netstat -an | grep 8000
```

---

## Troubleshooting

### Web UI Won't Load

**Check server is running:**
```bash
ps aux | grep artemis_server
curl http://localhost:8000/api/status
```

**Check firewall:**
```bash
sudo ufw allow 8000/tcp
```

**View logs:**
```bash
tail -f artemis.log
```

### Hunt Gets Stuck

**Check active hunts:**
```bash
curl http://localhost:8000/api/status | jq '.active_hunts'
```

**Restart server:**
```bash
sudo systemctl restart artemis
```

**Check Splunk connection:**
```bash
python test_splunk.py
```

### Plugin Not Working

**Check plugin is enabled:**
```bash
curl http://localhost:8000/api/plugins
```

**View plugin logs:**
```bash
# In Live Logs tab, look for plugin messages
```

**Manually test plugin:**
```python
from artemis.plugins.network_mapper import NetworkMapperPlugin

plugin = NetworkMapperPlugin({'output_dir': 'test_maps'})
plugin.initialize()
result = plugin.execute(network_connections=[], dns_queries=[])
print(result)
```

---

## Security Considerations

### Authentication (Coming Soon)

Current version has **no authentication**. Only run on:
- Localhost
- Trusted internal networks
- Behind VPN/firewall

**DO NOT expose to internet without authentication!**

### Securing the Deployment

**1. Reverse proxy with auth:**
```nginx
location / {
    auth_basic "Artemis";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://localhost:8000;
}
```

**2. TLS/HTTPS:**
```bash
# Use uvicorn with SSL
uvicorn artemis_server:app --ssl-keyfile key.pem --ssl-certfile cert.pem
```

**3. Firewall rules:**
```bash
sudo ufw allow from 10.0.0.0/8 to any port 8000
sudo ufw deny 8000
```

---

## Integration Examples

### Splunk Dashboard

Create a dashboard that queries Artemis via API:

```xml
<dashboard>
  <label>Artemis Threat Hunting</label>
  <row>
    <panel>
      <title>Recent Hunts</title>
      <single>
        <search>
          <query>
| rest services/server/info
| eval artemis_api="http://artemis-server:8000/api/hunts"
| fields artemis_api
          </query>
        </search>
      </single>
    </panel>
  </row>
</dashboard>
```

### Elasticsearch Integration

Send findings to Elasticsearch:

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(['http://localhost:9200'])

# Get hunt results
hunt = requests.get(f'http://localhost:8000/api/hunts/{hunt_id}').json()

# Index findings
for finding in hunt['findings']:
    es.index(index='artemis-findings', document=finding)
```

---

## What's Next?

- **Authentication** - API keys and user management
- **Multi-tenant** - Separate environments per team
- **Graph visualization** - Interactive network maps
- **Scheduled hunts** - Automated hunting on a schedule
- **Alert rules** - Trigger on specific finding patterns
- **Export formats** - CSV, PDF reports
- **Mobile app** - Monitor hunts on the go

---

## Need Help?

- **Web UI issues** → Check browser console (F12)
- **API questions** → See http://localhost:8000/docs
- **Plugin development** → Review `artemis/plugins/network_mapper.py`
- **Performance** → Check database size and worker threads

Happy Hunting! 🏹
