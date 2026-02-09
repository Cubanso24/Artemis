# Artemis Hunting Guide

## Quick Start

### Running Your First Hunt

```bash
cd ~/artemis
source venv/bin/activate
export SPLUNK_TOKEN="your-token-here"
python hunt.py
```

The hunt will:
1. Collect network data from Zeek/Suricata (last 1 hour)
2. Analyze network state and generate threat hypotheses
3. Deploy specialized hunting agents
4. Correlate findings across agents
5. Save results to `hunt_results/` directory

---

## Understanding the Output

### 1. Network State Analysis 📊

```
🔍 Network Metrics:
  • Active Connections: 1,234
  • DNS Query Rate: 45.2/sec
  • Total Data Transfer: 2.5 GB
  • Unique Internal IPs: 42
  • Unique External IPs: 156
```

**What to look for:**
- **High DNS query rate** (>100/sec) → Possible C2 beaconing or DGA activity
- **High external IPs** relative to internal → Possible reconnaissance or data exfiltration
- **Large data transfers** outside business hours → Potential exfiltration

---

### 2. Threat Hypotheses 🎯

Artemis generates hypotheses based on initial analysis:

```
[1] Unusual outbound traffic spike detected
    Type: anomaly_investigation
    Confidence: 0.75
    Priority: high
    Indicators: high_byte_ratio, after_hours, rare_destination
```

**Hypothesis Types:**
- `kill_chain_stage` → Specific attack phase detected
- `ttp_pattern` → Known technique pattern found
- `anomaly_investigation` → Statistical deviation from baseline
- `chain_of_events` → Multiple suspicious events correlated

**Confidence Levels:**
- `0.9+` → Very high confidence, likely real threat
- `0.7-0.9` → High confidence, investigate immediately
- `0.5-0.7` → Medium confidence, review when time permits
- `<0.5` → Low confidence, may be false positive

---

### 3. Agent Deployment 🤖

```
Deploying 5 specialized hunting agents:

  ✓ ReconnaissanceHunter      → Scanning for port scans, network sweeps, DNS recon
  ✓ C2Hunter                  → Detecting beaconing, DGA domains, suspicious callbacks
  ✓ LateralMovementHunter     → Tracking SMB/RDP lateral movement patterns
```

**Network-Focused Agents (Most relevant for your setup):**

1. **ReconnaissanceHunter**
   - Port scanning detection (SYN floods, sequential ports)
   - Network mapping (ICMP sweeps, ARP scans)
   - DNS reconnaissance (zone transfers, bulk queries)
   - Detects: Initial network footprinting

2. **C2Hunter**
   - Beaconing detection (regular intervals, consistent payload sizes)
   - DGA domain detection (high entropy, NXDOMAIN patterns)
   - Suspicious TLS certificates
   - Detects: Command & Control infrastructure

3. **LateralMovementHunter**
   - SMB lateral movement (admin$ shares, remote file access)
   - RDP connections between internal hosts
   - Pass-the-hash indicators
   - Detects: Internal network propagation

4. **CollectionExfiltrationHunter**
   - Large data transfers (>10MB to external IPs)
   - Unusual protocols (DNS/ICMP tunneling)
   - Cloud storage uploads outside business hours
   - Detects: Data theft attempts

---

### 4. Findings Analysis 🔍

Findings are grouped by severity:

#### 🔴 CRITICAL Severity
- **Immediate action required**
- High confidence + high impact
- Examples: Active C2 beaconing, large-scale exfiltration, ransomware indicators

#### 🟠 HIGH Severity
- **Investigate within hours**
- Clear attack indicators with medium-high confidence
- Examples: Port scanning, lateral movement, privilege escalation attempts

#### 🟡 MEDIUM Severity
- **Investigate within 24 hours**
- Suspicious behavior requiring context
- Examples: Unusual DNS patterns, after-hours activity, baseline deviations

#### 🔵 LOW Severity
- **Review when time permits**
- May be false positives or low-impact events
- Examples: Single anomaly, policy violations, informational alerts

---

### 5. Finding Details

Each finding includes:

```
[C2Hunter] Regular beaconing pattern detected
└─ Host 10.0.1.45 connecting to 192.0.2.100:443 every 60 seconds
└─ Confidence: 0.88
└─ MITRE: Command and Control (T1071), Exfiltration Over C2 Channel (T1041)
└─ Affected: 10.0.1.45
```

**Key Fields:**
- **Title** → What was detected
- **Description** → Details and context
- **Confidence** → How sure Artemis is (0.0-1.0)
- **MITRE** → Tactics and techniques from ATT&CK framework
- **Affected Assets** → Which hosts/IPs are involved

---

### 6. Meta-Learner Analysis 🧠

```
📈 Overall Threat Assessment:
  • Total Findings: 12
  • Overall Confidence: 0.82
  • Corroborated Findings: 5
  • Kill Chain Sequences: 2
```

**Important Metrics:**

- **Corroborated Findings** → Multiple agents agree on the same threat
  - Higher corroboration = higher confidence
  - Formula: base_confidence × (1 + 0.2 × confirming_agents)

- **Kill Chain Sequences** → Multi-stage attacks detected
  - Examples: Recon → Initial Access → Lateral Movement
  - These are HIGHEST priority (multiplied by 1.5×)

- **Attack Campaigns** → Related findings grouped together
  - Shows the full scope of an attack
  - Tracks progression through MITRE stages

---

## Analyzing Results Files

### JSON Output (`hunt_results/hunt_YYYYMMDD_HHMMSS.json`)

```json
{
  "timestamp": "20260209_091500",
  "network_state": {
    "active_connections": 1234,
    "dns_query_rate": 45.2,
    "is_business_hours": false
  },
  "agent_results": {
    "C2Hunter": {
      "findings_count": 3,
      "findings": [...]
    }
  },
  "aggregated_results": {
    "overall_confidence": 0.82,
    "attack_campaigns": [...]
  }
}
```

**Use Cases:**
- Feed into SIEM/SOAR platforms
- Build custom dashboards
- Track metrics over time
- Create reports for management

### Text Summary (`hunt_results/latest_hunt.txt`)

Quick reference for the most recent hunt. Great for:
- Quick checks
- Sharing with teammates
- Scripting/automation

---

## Improving Artemis Over Time

### 1. Track False Positives

When you find a false positive:

```python
# In future: Add to false positive tuning
# artemis/tuning/false_positives.yaml

- agent: C2Hunter
  finding: "Regular beaconing pattern"
  reason: "Legitimate software update check"
  whitelist:
    - destination: "updates.example.com"
    - interval_tolerance: 60
```

### 2. Adjust Confidence Thresholds

If you're getting too many low-confidence alerts:

```python
# artemis/agents/base_agent.py
MIN_CONFIDENCE_THRESHOLD = 0.7  # Increase from 0.5
```

### 3. Add Custom Detection Rules

Example: Detect beaconing to specific suspicious ports:

```python
# In C2Hunter agent
SUSPICIOUS_PORTS = [4444, 5555, 8080, 8888, 31337]

if dest_port in SUSPICIOUS_PORTS and is_beaconing:
    confidence *= 1.3  # Boost confidence
```

### 4. Tune Detection Parameters

Current defaults you can adjust:

**Beaconing Detection:**
```python
# artemis/agents/c2_hunter.py
BEACONING_INTERVAL_TOLERANCE = 0.1  # ±10% variation
MIN_BEACON_COUNT = 5  # Need 5+ connections
```

**Port Scanning:**
```python
# artemis/agents/reconnaissance_hunter.py
PORT_SCAN_THRESHOLD = 20  # Ports in 60 seconds
SYN_FLOOD_THRESHOLD = 100  # SYN packets
```

**Data Exfiltration:**
```python
# artemis/agents/collection_exfiltration_hunter.py
LARGE_TRANSFER_THRESHOLD = 10 * 1024 * 1024  # 10 MB
```

### 5. Build Historical Baselines

Track normal behavior patterns:

```bash
# Run hunts regularly and save metrics
python hunt.py --time-range '-1h' >> hunt_log.txt

# Analyze patterns over time
# Use hunt_results/*.json to build baseline profiles
```

### 6. Compare Hunts Over Time

```python
# Example analysis script
import json
from pathlib import Path

hunt_files = sorted(Path("hunt_results").glob("hunt_*.json"))

for hunt_file in hunt_files[-10:]:  # Last 10 hunts
    with open(hunt_file) as f:
        data = json.load(f)
        print(f"{data['timestamp']}: {data['aggregated_results']['overall_confidence']}")
```

---

## Advanced Hunting Techniques

### 1. Targeted Hunts

Hunt specific IPs or subnets:

```python
# Modify hunt.py to filter data
hunting_data = {
    'network_connections': [
        conn for conn in all_connections
        if conn['source_ip'].startswith('10.0.1.')
    ]
}
```

### 2. Time-Based Analysis

Compare business hours vs. after-hours:

```bash
# Business hours
python hunt.py --time-range 'earliest=-1h@h latest=@h'

# After hours (night)
python hunt.py --time-range 'earliest=-1h@d+22h latest=@d+6h'
```

### 3. Hunt for Specific TTPs

Focus on lateral movement:

```python
# Deploy only specific agents
coordinator.hunt(
    network_state=network_state,
    hunting_data=hunting_data,
    force_agents=['LateralMovementHunter', 'CredentialAccessHunter']
)
```

---

## Common Detection Patterns

### Pattern 1: C2 Beaconing

**Indicators:**
- Regular connection intervals (±10% tolerance)
- Small, consistent payload sizes
- Connections to same external IP
- Activity outside business hours

**Example Finding:**
```
Host 10.0.1.50 → 198.51.100.25:443
Interval: 60s (CV: 0.05)
Payload: ~1.2KB each
Duration: 3 hours
```

**Investigation:**
1. Check destination IP reputation
2. Analyze TLS certificate
3. Review process on source host
4. Check for other hosts connecting to same destination

---

### Pattern 2: Internal Reconnaissance

**Indicators:**
- High rate of connection attempts
- Sequential port scanning
- Multiple NXDOMAIN DNS responses
- ICMP sweeps across subnet

**Example Finding:**
```
Host 10.0.1.75 scanned 245 ports on 10.0.2.0/24
Time: 2 minutes
Protocol: TCP SYN
Success rate: 12%
```

**Investigation:**
1. Identify source host owner
2. Check if authorized security scanning
3. Review source host for compromise
4. Check lateral movement from this host

---

### Pattern 3: Data Exfiltration

**Indicators:**
- Large outbound transfers (>10MB)
- Unusual destination (cloud storage, file sharing)
- After-hours activity
- Compressed/encrypted files

**Example Finding:**
```
Host 10.0.1.100 → dropbox.com
Transfer: 250MB
Time: 2:30 AM
Protocol: HTTPS
```

**Investigation:**
1. Identify user and workstation
2. Check file server access logs
3. Review endpoint logs for file compression
4. Check for other exfil indicators (staging area)

---

## Metrics to Track

### Detection Effectiveness

1. **True Positive Rate**
   - Findings that were real threats
   - Goal: >70%

2. **False Positive Rate**
   - Findings that were not threats
   - Goal: <30%

3. **Mean Time to Detect (MTTD)**
   - How quickly Artemis finds threats
   - Current: Near real-time with hourly hunts

4. **Coverage**
   - % of MITRE ATT&CK techniques detectable
   - Network-only: ~40% coverage
   - Network + Host logs: ~75% coverage

### Agent Performance

Track which agents are most useful:

```
Agent                      | Findings | True Positives | FP Rate
---------------------------|----------|----------------|--------
C2Hunter                   | 45       | 38             | 15%
ReconnaissanceHunter       | 32       | 28             | 12%
LateralMovementHunter      | 18       | 15             | 17%
CollectionExfiltrationHunt | 12       | 10             | 17%
```

---

## Troubleshooting

### No Findings Detected

**Possible Reasons:**
1. Network is actually clean (good!)
2. Time range too short (try `-24h`)
3. Low activity period (hunt during business hours)
4. Detection thresholds too high

**Solutions:**
- Increase time range
- Lower confidence thresholds
- Review raw Splunk data to confirm activity exists

### Too Many False Positives

**Solutions:**
1. Increase confidence threshold
2. Add whitelisting for known-good IPs/domains
3. Tune detection parameters
4. Build better baselines

### Agent Taking Too Long

**Solutions:**
1. Reduce time range
2. Add sampling to large datasets
3. Use filters to reduce data volume
4. Optimize Splunk queries

---

## Next Steps

1. **Run regular hunts** (hourly/daily)
2. **Build baselines** over 1-2 weeks
3. **Track metrics** (findings, true positives, false positives)
4. **Tune detections** based on your environment
5. **Add Windows logs** for host-based detection
6. **Integrate with SIEM** for alerting
7. **Create custom dashboards** for visualization

---

## Getting Help

- Review code in `artemis/agents/` to understand detection logic
- Check `hunt_results/` for detailed JSON output
- Modify detection parameters in agent files
- Add logging for debugging: `coordinator.logger.setLevel(logging.DEBUG)`

---

Happy Hunting! 🏹
