#!/usr/bin/env python3
"""
Check the raw JSON structure of Zeek data.
"""

import os
import sys
import json
sys.path.insert(0, '/home/user/Artemis')

from artemis.integrations.splunk_connector import SplunkConnector

# Get credentials
host = os.environ.get('SPLUNK_HOST', '10.25.11.86')
token = os.environ.get('SPLUNK_TOKEN', 'your-token-here')

print(f"Connecting to Splunk at {host}...")
splunk = SplunkConnector(host=host, port=8089, token=token, verify_ssl=False)

print("\n" + "="*80)
print("ZEEK CONN JSON STRUCTURE")
print("="*80)

query = "search index=zeek_conn | head 1"
events = splunk.query(query, earliest_time="-1h", max_results=1)

if events:
    raw = events[0].get('_raw', '')
    print(f"\nRaw JSON:\n{raw}\n")

    try:
        data = json.loads(raw)
        print("Parsed fields:")
        for key, value in sorted(data.items()):
            print(f"  {key:20s} = {value}")
    except:
        print("Failed to parse JSON")

print("\n" + "="*80)
print("ZEEK DNS JSON STRUCTURE")
print("="*80)

query = "search index=zeek_dns | head 1"
events = splunk.query(query, earliest_time="-1h", max_results=1)

if events:
    raw = events[0].get('_raw', '')
    print(f"\nRaw JSON:\n{raw}\n")

    try:
        data = json.loads(raw)
        print("Parsed fields:")
        for key, value in sorted(data.items()):
            print(f"  {key:20s} = {value}")
    except:
        print("Failed to parse JSON")

print("\n" + "="*80)
print("\nNOW TESTING JSON EXTRACTION IN SPLUNK")
print("="*80)

# Test if spath works
query = '''
search index=zeek_conn
| spath
| head 1
| table id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes conn_state
'''

print(f"\nQuery with spath:\n{query}\n")
events = splunk.query(query, earliest_time="-1h", max_results=1)

if events:
    print(f"✓ Retrieved {len(events)} events with spath")
    print("\nExtracted fields:")
    for key, value in events[0].items():
        print(f"  {key:20s} = {value}")
else:
    print("❌ spath didn't work")
