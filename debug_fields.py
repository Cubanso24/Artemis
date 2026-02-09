#!/usr/bin/env python3
"""
Check what fields are actually available in Zeek data.
"""

import os
import sys
sys.path.insert(0, '/home/user/Artemis')

from artemis.integrations.splunk_connector import SplunkConnector

# Get credentials
host = os.environ.get('SPLUNK_HOST', '10.25.11.86')
token = os.environ.get('SPLUNK_TOKEN', 'your-token-here')

print(f"Connecting to Splunk at {host}...")
splunk = SplunkConnector(host=host, port=8089, token=token, verify_ssl=False)

print("\n" + "="*80)
print("CHECKING AVAILABLE FIELDS IN ZEEK_CONN")
print("="*80)

# Get raw events WITHOUT filtering fields
query = "search index=zeek_conn | head 1"
events = splunk.query(query, earliest_time="-1h", max_results=1)

if events:
    print("\n✓ All available fields in zeek_conn:")
    for key in sorted(events[0].keys()):
        value = str(events[0][key])[:50]  # Truncate long values
        print(f"  {key:30s} = {value}")
else:
    print("❌ No events found")

print("\n" + "="*80)
print("CHECKING AVAILABLE FIELDS IN ZEEK_DNS")
print("="*80)

query = "search index=zeek_dns | head 1"
events = splunk.query(query, earliest_time="-1h", max_results=1)

if events:
    print("\n✓ All available fields in zeek_dns:")
    for key in sorted(events[0].keys()):
        value = str(events[0][key])[:50]
        print(f"  {key:30s} = {value}")
else:
    print("❌ No events found")

print("\n" + "="*80)
