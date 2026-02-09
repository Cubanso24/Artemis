# Historical Data Hunting Strategy

## Overview

With weeks of historical data, you can use Artemis in **three powerful ways**:

1. **Baseline Building** → Establish normal behavior patterns
2. **Historical Threat Hunt** → Find past compromises you might have missed
3. **Ongoing Monitoring** → Real-time threat detection

---

## Strategy 1: Baseline Building (WEEKS 1-2)

### Goal
Understand what "normal" looks like in your environment so you can spot anomalies.

### Recommended Approach

**Use 1-2 weeks of KNOWN-GOOD data** (before any suspected incidents):

```bash
# Hunt in 6-hour windows across 2 weeks
python bulk_hunt.py --days 14 --window 6
```

### What This Does

1. **Analyzes 56 time windows** (4 windows/day × 14 days)
2. **Builds baseline metrics**:
   - Normal DNS query rates
   - Typical connection counts
   - Standard data transfer volumes
   - Business hours vs. after-hours patterns
3. **Identifies false positives**:
   - Legitimate software that looks suspicious
   - Normal admin activities
   - Scheduled tasks and backups

### After Running

Review the results:

```bash
cd bulk_hunt_results
cat bulk_hunt_summary.json

# Look at baseline metrics:
{
  "baseline_metrics": {
    "dns_query_rate": {
      "average": 42.5,
      "min": 12.0,
      "max": 98.3
    },
    "active_connections": {
      "average": 850,
      "min": 234,
      "max": 2150
    }
  }
}
```

### Action Items

1. **Document normal ranges**:
   ```
   Normal DNS rate: 30-60 queries/sec
   Normal connections: 500-1500
   Normal after-hours: <200 connections
   ```

2. **Whitelist known-good findings**:
   - Backup software connections
   - Monitoring tool beaconing
   - Software update checks
   - Admin scanning tools

3. **Tune thresholds** based on your environment:
   ```python
   # artemis/agents/c2_hunter.py
   # If your baseline shows software updating every 5 minutes:
   BEACONING_INTERVAL_TOLERANCE = 0.15  # Allow more variance
   ```

---

## Strategy 2: Historical Threat Hunt (WEEK 3)

### Goal
Find threats that were lurking in your network but went undetected.

### Recommended Approach

**Hunt across ALL available data** looking for patterns:

```bash
# Hunt last 30 days in 12-hour windows
python bulk_hunt.py --days 30 --window 12
```

### What to Look For

1. **Persistent Threats**
   - Same suspicious IPs appearing across multiple time windows
   - Long-term beaconing patterns (weeks/months)
   - Slow data exfiltration

2. **Attack Campaigns**
   - Recon → Access → Lateral Movement → Exfil sequences
   - Multiple compromised hosts
   - Coordinated attacker activity

3. **Dormant Backdoors**
   - Infrequent C2 callbacks
   - Beaconing that only happens at specific times
   - Low-and-slow data theft

### Analysis Workflow

**Step 1: Identify High-Risk Windows**

```bash
# The summary shows windows with most findings
cd bulk_hunt_results
cat bulk_hunt_summary.json | jq '.high_risk_windows'

# Output:
[
  {
    "label": "2026-01-15 14:00",
    "findings": 23,
    "confidence": 0.85
  },
  {
    "label": "2026-01-15 18:00",
    "findings": 18,
    "confidence": 0.78
  }
]
```

**Step 2: Deep Dive on Suspicious Windows**

```bash
# Examine specific window
cat window_2026-01-15_14:00.json | jq '.agent_results'

# Look for:
# - Multiple agents detecting same hosts
# - High confidence findings
# - MITRE kill chain progression
```

**Step 3: Track Threats Across Time**

```bash
# Find all windows mentioning a specific IP
grep -r "192.0.2.100" bulk_hunt_results/*.json

# This shows if an attacker was active across multiple days
```

**Step 4: Build Attack Timeline**

```
Timeline for Incident 2026-01-15:

2026-01-15 14:00 → Port scanning detected (10.0.1.50)
2026-01-15 16:00 → Lateral movement via SMB (10.0.1.50 → 10.0.1.75)
2026-01-15 18:00 → Large data transfer (10.0.1.75 → 198.51.100.25)
2026-01-16 02:00 → C2 beaconing established (10.0.1.75 → 198.51.100.25)
```

---

## Strategy 3: Ongoing Monitoring (WEEK 4+)

### Goal
Real-time threat detection using your tuned baseline.

### Recommended Approach

**Run regular hunts on recent data**:

```bash
# Option A: Hourly hunts (automated)
# Add to crontab:
0 * * * * cd /home/user/artemis && python hunt.py --time-range '-1h'

# Option B: Daily comprehensive hunts
0 8 * * * cd /home/user/artemis && python hunt.py --time-range '-24h'

# Option C: Manual investigation hunts
python hunt.py --time-range '-1h'  # Last hour
python hunt.py --time-range '-4h'  # Last 4 hours
```

### Alert Workflow

1. **High Priority** (CRITICAL/HIGH findings)
   - Investigate immediately
   - Check if it matches known baseline patterns
   - If new: escalate

2. **Medium Priority** (MEDIUM findings)
   - Review within 24 hours
   - Compare against historical data
   - Track over multiple hunts

3. **Low Priority** (LOW findings)
   - Bulk review weekly
   - Look for patterns across time
   - Add to whitelist if benign

---

## Recommended Time Windows

Choose window size based on your goals:

### 1-Hour Windows
**Best for:** Real-time monitoring, catching active attacks
```bash
python bulk_hunt.py --days 1 --window 1
```
- **Pros**: High resolution, catches short-lived activity
- **Cons**: Many windows to process, slower
- **Use when**: Investigating a specific incident, real-time monitoring

### 6-Hour Windows
**Best for:** Balanced approach, good for most scenarios
```bash
python bulk_hunt.py --days 7 --window 6
```
- **Pros**: Good balance of detail and speed
- **Cons**: Might miss very brief attacks
- **Use when**: Weekly threat hunts, baseline building

### 12-Hour Windows
**Best for:** Long-term analysis, trend detection
```bash
python bulk_hunt.py --days 30 --window 12
```
- **Pros**: Fast processing, good for big picture
- **Cons**: Less granular, might aggregate unrelated events
- **Use when**: Monthly reviews, hunting persistent threats

### 24-Hour Windows
**Best for:** Quick overview, high-level trends
```bash
python bulk_hunt.py --days 90 --window 24
```
- **Pros**: Very fast, good for quarterly reviews
- **Cons**: Loses a lot of detail
- **Use when**: Executive reporting, long-term trend analysis

---

## Example Workflows

### Workflow 1: "I Just Set Up Artemis"

**Week 1: Baseline Building**
```bash
# Hunt last 2 weeks in 6-hour windows (known-good data)
python bulk_hunt.py --days 14 --window 6

# Review results, document baselines
cd bulk_hunt_results
python -m json.tool bulk_hunt_summary.json

# Tune thresholds based on false positives
vim artemis/agents/c2_hunter.py  # Adjust detection params
```

**Week 2: Historical Sweep**
```bash
# Hunt all available data
python bulk_hunt.py --days 30 --window 12

# Focus on high-risk windows
cd bulk_hunt_results
jq '.high_risk_windows[]' bulk_hunt_summary.json
```

**Week 3: Ongoing Monitoring**
```bash
# Daily hunts
python hunt.py --time-range '-24h' | tee -a hunt_log.txt

# Weekly deep dive
python bulk_hunt.py --days 7 --window 6
```

---

### Workflow 2: "I Suspect a Breach in the Past"

**Step 1: Wide Net (Quick Overview)**
```bash
# Hunt 60 days in 24-hour windows
python bulk_hunt.py --days 60 --window 24
```

**Step 2: Zoom In on Suspicious Periods**
```bash
# If Jan 15-20 looks suspicious, zoom in with 1-hour windows
# Modify bulk_hunt.py or use multiple runs:
python hunt.py --time-range 'earliest=1/15/2026:00:00:00 latest=1/16/2026:00:00:00'
python hunt.py --time-range 'earliest=1/16/2026:00:00:00 latest=1/17/2026:00:00:00'
# ... continue for each day
```

**Step 3: Build Attack Timeline**
```bash
# Extract all findings from suspect period
cd bulk_hunt_results
jq '.agent_results' window_2026-01-15_*.json > incident_timeline.json
```

**Step 4: Pivot on Indicators**
```bash
# If you find suspicious IP 198.51.100.25, search ALL windows
grep -r "198.51.100.25" bulk_hunt_results/*.json > attacker_activity.txt

# Check how far back it goes
# Check what other hosts communicated with it
```

---

### Workflow 3: "Monthly Security Review"

**Day 1: Full Month Hunt**
```bash
# Hunt last 30 days
python bulk_hunt.py --days 30 --window 12
```

**Day 2-3: Analysis**
```bash
# Generate metrics
cd bulk_hunt_results
cat bulk_hunt_summary.json

# Compare to previous month
# Look for trend changes:
# - More findings this month?
# - New attack types?
# - Increase in specific indicators?
```

**Day 4: Deep Dives**
```bash
# Investigate any high-risk windows
# Re-hunt with finer granularity if needed
python bulk_hunt.py --days 2 --window 1  # For specific suspicious dates
```

**Day 5: Report & Tune**
```bash
# Create summary report
# Update whitelists
# Tune thresholds
# Document lessons learned
```

---

## Performance Optimization

### For Large Data Sets

If you have massive amounts of data:

**1. Start with Larger Windows**
```bash
# Quick pass with 24-hour windows
python bulk_hunt.py --days 30 --window 24

# Then zoom in on interesting periods
python bulk_hunt.py --days 2 --window 1  # For specific dates
```

**2. Use Time Sampling**

Modify queries in `splunk_connector.py` to sample:
```python
# Add to queries:
query += " | sample ratio=0.5"  # Sample 50% of events
```

**3. Focus on High-Value Data**

Hunt specific indexes only:
```python
# In bulk_hunt.py, modify data collection:
hunting_data = {
    'network_connections': pipeline.splunk_connector.get_network_connections(time_range),
    'dns_queries': pipeline.splunk_connector.get_dns_queries(time_range)
    # Skip others for faster processing
}
```

**4. Parallel Processing**

Run multiple time ranges in parallel:
```bash
# Terminal 1
python bulk_hunt.py --days 15 --window 6  # Jan 1-15

# Terminal 2
python bulk_hunt.py --days 15 --window 6  # Jan 16-31
```

---

## Tracking Improvements

### Metrics to Monitor

Create a tracking spreadsheet:

| Week | Windows Hunted | Total Findings | True Positives | False Positives | FP Rate |
|------|----------------|----------------|----------------|-----------------|---------|
| 1    | 56             | 234            | ?              | ?               | ?%      |
| 2    | 56             | 189            | 12             | 177             | 93.7%   |
| 3    | 56             | 45             | 32             | 13              | 28.9%   |
| 4    | 56             | 38             | 35             | 3               | 7.9%    |

**Goal: Reduce false positive rate to <10%**

### Questions to Ask

After each bulk hunt:

1. **Coverage**: Did I hunt all the time I intended?
2. **Findings**: How many findings per window?
3. **True Positives**: How many were real threats?
4. **False Positives**: What caused them? Can I tune them out?
5. **Missed Threats**: Did I miss anything I later discovered?
6. **Performance**: How long did it take? Can I optimize?

---

## Advanced: Custom Analysis Scripts

### Extract Top Talkers Across Time

```bash
# Find most active internal IPs
cd bulk_hunt_results
jq -r '.agent_results[].findings[].affected_assets[]' window_*.json | \
  sort | uniq -c | sort -rn | head -20

# Output:
#  45 10.0.1.75   ← This host appears in 45 findings!
#  23 10.0.1.50
#  12 10.0.2.100
```

### Track Confidence Trends

```bash
# Average confidence over time
jq '.aggregated_results.overall_confidence' bulk_hunt_results/window_*.json | \
  awk '{sum+=$1; n++} END {print "Average confidence:", sum/n}'
```

### Find Kill Chain Sequences

```bash
# Windows with multiple MITRE tactics (multi-stage attacks)
jq 'select(.aggregated_results.kill_chain_sequences > 0) |
    {window: .window.label, sequences: .aggregated_results.kill_chain_sequences}' \
    bulk_hunt_results/window_*.json
```

---

## Summary: Best Practices

### DO ✅

1. **Start with baseline building** (2 weeks of known-good data)
2. **Use appropriate window sizes** (6 hours for most scenarios)
3. **Review results systematically** (high-risk windows first)
4. **Track metrics over time** (improve detection accuracy)
5. **Tune based on your environment** (reduce false positives)
6. **Hunt regularly** (weekly or daily for ongoing monitoring)
7. **Save all results** (for historical comparison and reporting)

### DON'T ❌

1. **Don't hunt ALL data at once** in 1-hour windows (too slow)
2. **Don't ignore false positives** (tune them out)
3. **Don't trust findings blindly** (validate and investigate)
4. **Don't use the same thresholds everywhere** (tune per environment)
5. **Don't skip documentation** (track what you learn)
6. **Don't forget to compare time periods** (trends matter)

---

## Quick Reference Commands

```bash
# Baseline building (2 weeks, 6-hour windows)
python bulk_hunt.py --days 14 --window 6

# Weekly threat hunt
python bulk_hunt.py --days 7 --window 6

# Monthly review
python bulk_hunt.py --days 30 --window 12

# Real-time monitoring
python hunt.py --time-range '-1h'

# Incident investigation (specific day, 1-hour windows)
python bulk_hunt.py --days 1 --window 1

# Long-term trend analysis (3 months, daily windows)
python bulk_hunt.py --days 90 --window 24
```

---

## Getting Started TODAY

**If you have 2+ weeks of data:**

```bash
cd ~/artemis
git pull
source venv/bin/activate

# Phase 1: Quick overview (takes ~30 min)
python bulk_hunt.py --days 7 --window 12

# Phase 2: Review results
cd bulk_hunt_results
cat bulk_hunt_summary.json

# Phase 3: Deep dive on interesting windows
cat window_YYYY-MM-DD_HH:MM.json | jq '.agent_results'

# Phase 4: Tune and repeat
vim ../artemis/agents/c2_hunter.py  # Adjust thresholds
python bulk_hunt.py --days 7 --window 6  # Re-hunt with better tuning
```

Happy hunting! 🏹
