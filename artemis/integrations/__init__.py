"""
Data integration layer for connecting Artemis to security infrastructure.

Provides connectors for:
- Splunk (log queries)
- Security Onion (PCAP analysis)
- PCAP feature extraction
- Real-time data streaming
"""

from artemis.integrations.splunk_connector import SplunkConnector
from artemis.integrations.security_onion_connector import SecurityOnionConnector
from artemis.integrations.pcap_analyzer import PCAPAnalyzer
from artemis.integrations.data_pipeline import DataPipeline

__all__ = [
    "SplunkConnector",
    "SecurityOnionConnector",
    "PCAPAnalyzer",
    "DataPipeline",
]
