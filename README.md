# Artemis - Hierarchical Threat Hunting System

**A meta-learning coordinator orchestrating specialized hunting agents for advanced cybersecurity threat detection**

## Overview

Artemis is an intelligent, multi-agent threat hunting system that uses meta-learning to coordinate specialized hunting agents. Each agent is an expert in specific attack detection domains (reconnaissance, initial access, execution, etc.), while the meta-learner orchestrates them using context-aware decision-making and adaptive learning.

### Key Features

- **9 Specialized Hunting Agents**: Each mastering specific MITRE ATT&CK tactics
- **Meta-Learning Coordination**: Intelligent agent orchestration with context awareness
- **Adaptive Learning**: Continuous improvement through analyst feedback
- **Kill Chain Progression**: Automatic detection of multi-stage attacks
- **Explainable AI**: Every detection includes detailed evidence and reasoning
- **Flexible Deployment**: Parallel, sequential, or adaptive agent activation modes

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Meta-Learner Coordinator                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Context    │  │    Agent     │  │  Confidence  │      │
│  │  Assessment  │→ │  Selection   │→ │ Aggregation  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         ↓                                     ↑              │
│  ┌──────────────────────────────────────────┐│              │
│  │      Adaptive Learning Module            ││              │
│  └──────────────────────────────────────────┘│              │
└────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│                 Specialized Hunting Agents                   │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ Agent 1:     │ Agent 2:     │ Agent 3:     │ Agent 4:       │
│ Recon &      │ Initial      │ Execution &  │ Credential     │
│ Discovery    │ Access       │ Persistence  │ Access         │
├──────────────┼──────────────┼──────────────┼────────────────┤
│ Agent 5:     │ Agent 6:     │ Agent 7:     │ Agent 8:       │
│ Lateral      │ Collection & │ C2           │ Defense        │
│ Movement     │ Exfiltration │ Detection    │ Evasion        │
├──────────────┴──────────────┴──────────────┴────────────────┤
│ Agent 9: Impact & Destruction                                │
└──────────────────────────────────────────────────────────────┘
```

## Installation

### Requirements

- Python 3.8+
- NumPy >= 1.20.0

### Install from source

```bash
git clone https://github.com/yourusername/artemis.git
cd artemis
pip install -r requirements.txt
```

## Quick Start

```python
from artemis import MetaLearnerCoordinator
from datetime import datetime

# Initialize coordinator
coordinator = MetaLearnerCoordinator()

# Prepare threat hunting data
hunting_data = {
    "network_connections": [...],
    "dns_queries": [...],
    "process_logs": [...],
    "authentication_logs": [...]
}

# Execute threat hunt
assessment = coordinator.hunt(data=hunting_data)

# Review results
print(f"Confidence: {assessment['final_confidence']:.2f}")
print(f"Severity: {assessment['severity'].value}")
print(f"Alert Level: {assessment['alert_level']}")
print(f"MITRE Techniques: {assessment['mitre_techniques']}")

# Provide analyst feedback for adaptive learning
coordinator.provide_feedback(
    assessment,
    feedback_type="true_positive",
    analyst_notes="Confirmed APT activity"
)
```

## Specialized Hunting Agents

### Agent 1: Reconnaissance & Discovery Hunter
**MITRE Tactics**: TA0043 (Reconnaissance), TA0007 (Discovery)

Detects:
- Network scanning (port sweeps, host enumeration)
- Active Directory enumeration
- Cloud resource discovery
- DNS query patterns indicating reconnaissance
- LDAP queries for domain mapping

### Agent 2: Initial Access & Delivery Hunter
**MITRE Tactics**: TA0001 (Initial Access)

Detects:
- Phishing emails (attachments, links)
- Exploit delivery mechanisms
- Drive-by downloads
- Supply chain compromise indicators
- Valid account abuse
- Geographic anomalies (impossible travel)

### Agent 3: Execution & Persistence Hunter
**MITRE Tactics**: TA0002 (Execution), TA0003 (Persistence)

Detects:
- PowerShell/command-line abuse
- Living-off-the-land binaries (LOLBins)
- Scheduled task/cron job creation
- Registry modifications
- WMI event subscriptions
- Service creation/modification

### Agent 4: Credential Access Hunter
**MITRE Tactics**: TA0006 (Credential Access)

Detects:
- Credential dumping (LSASS, SAM, NTDS.dit)
- Kerberoasting
- Pass-the-hash/pass-the-ticket
- Brute force attempts
- Password spraying
- Keylogging indicators

### Agent 5: Lateral Movement Hunter
**MITRE Tactics**: TA0008 (Lateral Movement)

Detects:
- Remote service sessions (RDP, SSH, WinRM)
- SMB/admin share access patterns
- Remote execution (PsExec, WMI, DCOM)
- Pass-the-hash lateral movement
- Unusual service account activity

### Agent 6: Collection & Exfiltration Hunter
**MITRE Tactics**: TA0009 (Collection), TA0010 (Exfiltration)

Detects:
- Data staging
- Compression/archiving of sensitive data
- Large data transfers
- Cloud storage uploads
- DNS tunneling
- Screenshot/clipboard capture

### Agent 7: Command & Control (C2) Hunter
**MITRE Tactics**: TA0011 (Command and Control)

Detects:
- Beaconing (periodic callbacks)
- Domain Generation Algorithm (DGA) identification
- Uncommon protocol usage
- Tor/VPN/proxy detection
- Application layer protocol abuse
- Fast-flux DNS patterns

### Agent 8: Defense Evasion Hunter
**MITRE Tactics**: TA0005 (Defense Evasion)

Detects:
- Log deletion/modification
- Security tool disabling
- Process injection/hollowing
- Rootkit indicators
- Timestomping
- Masquerading

### Agent 9: Impact & Destruction Hunter
**MITRE Tactics**: TA0040 (Impact)

Detects:
- Ransomware behavior
- Data destruction patterns
- Service/resource disruption
- Cryptomining activity
- Resource hijacking

## Meta-Learner Coordination

### Context Assessment
The meta-learner continuously monitors:
- Network state (time, traffic patterns, system load)
- Alert history and trends
- Threat intelligence feeds
- Critical asset status
- Business context (maintenance windows, etc.)

### Agent Selection
Agents are selected using a priority scoring system:

```
Priority_Score = (Threat_Relevance × 0.4) +
                 (Asset_Criticality × 0.3) +
                 (Temporal_Urgency × 0.2) +
                 (Agent_Confidence_History × 0.1)
```

### Deployment Modes

**Adaptive Mode** (Default)
- Intelligent agent selection based on context
- Resource-efficient
- Best for routine monitoring

**Sequential Mode**
- Agents activated based on kill chain progression
- Follows logical attack flow
- Optimal for investigating specific incidents

**Parallel Mode**
- All agents run simultaneously
- Resource-intensive
- Used for high-priority alerts or known active threats

### Confidence Aggregation

The meta-learner aggregates findings using:

1. **Corroboration Scoring**: Boosts confidence when multiple agents detect related activity
2. **Kill Chain Progression Weighting**: Higher confidence for sequential attack stages
3. **False Positive Dampening**: Adjusts for agent historical accuracy

```
Final_Confidence = max(Agent_Confidences) × Corroboration_Boost × Chain_Multiplier × FP_Dampening
```

### Alert Levels

- **Critical** (confidence ≥ 0.9): Auto-escalate to SOC
- **High** (0.7-0.9): Analyst review recommended
- **Medium** (0.5-0.7): Watchlist monitoring
- **Low** (<0.5): Log for pattern analysis

## Adaptive Learning

Artemis continuously improves through:

### Analyst Feedback Integration
```python
coordinator.provide_feedback(
    assessment,
    feedback_type="true_positive",  # or "false_positive", "uncertain"
    analyst_notes="Confirmed ransomware attack"
)
```

### Attack Campaign Playbooks
The system builds playbooks for known attack patterns:
- Records successful agent activation sequences
- Associates MITRE techniques with effective detection strategies
- Automatically applies learned playbooks to similar threats

### Performance Tracking
- Time-to-detection optimization
- False positive rate minimization
- Agent confidence calibration
- Resource efficiency tuning

## Example Scenarios

### Phishing Campaign Detection
```bash
python -m artemis.examples.scenario_phishing
```

Demonstrates detection of:
1. Initial phishing email
2. Macro execution
3. PowerShell abuse and persistence
4. C2 beaconing

### Ransomware Early Detection
```bash
python -m artemis.examples.scenario_ransomware
```

Shows early detection through:
1. Suspicious scheduled task
2. Defense evasion (log clearing)
3. Rapid file encryption

## Configuration

Create a configuration file:

```json
{
  "deployment_mode": "adaptive",
  "enable_parallel_execution": true,
  "max_workers": 4,
  "critical_threshold": 0.9,
  "high_threshold": 0.7,
  "medium_threshold": 0.5,
  "enable_adaptive_learning": true,
  "log_level": "INFO"
}
```

Load configuration:

```python
from artemis.config import ArtemisConfig

config = ArtemisConfig.from_file("config.json")
coordinator = MetaLearnerCoordinator(
    deployment_mode=config.deployment_mode,
    max_workers=config.max_workers
)
```

## API Reference

### MetaLearnerCoordinator

```python
coordinator = MetaLearnerCoordinator(
    deployment_mode="adaptive",  # adaptive, parallel, sequential
    enable_parallel_execution=True,
    max_workers=4
)

# Execute threat hunt
assessment = coordinator.hunt(
    data=hunting_data,
    initial_signals=None,  # Optional initial alerts
    context_data=None      # Optional network state context
)

# Provide feedback
coordinator.provide_feedback(assessment, "true_positive", "analyst notes")

# Get statistics
stats = coordinator.get_statistics()
agent_metrics = coordinator.get_agent_metrics()
```

## Performance Metrics

Artemis tracks:
- Total hunts executed
- Detection rate
- False positive rate
- Time-to-detection
- Agent activation patterns
- Most correlated agents
- Playbook effectiveness

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Citation

If you use Artemis in your research, please cite:

```bibtex
@software{artemis_threat_hunting,
  title = {Artemis: Hierarchical Threat Hunting System},
  author = {Your Name},
  year = {2025},
  url = {https://github.com/yourusername/artemis}
}
```

## Acknowledgments

- MITRE ATT&CK® framework
- Threat intelligence community
- SOC analysts and threat hunters worldwide

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Artemis** - Advanced threat hunting through intelligent multi-agent collaboration
