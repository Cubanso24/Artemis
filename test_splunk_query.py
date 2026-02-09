#!/usr/bin/env python3
"""
Test Splunk queries to see what data is being returned.
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
print("TESTING NETWORK CONNECTIONS QUERY")
print("="*80)

# Test the actual query being run
query = '''
search index=zeek_conn OR index=suricata
| eval timestamp=_time
| table _time id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes conn_state
| rename "id.orig_h" as source_ip, "id.resp_h" as destination_ip, "id.resp_p" as destination_port, proto as protocol, orig_bytes as bytes_in, resp_bytes as bytes_out
'''

print(f"\nQuery: {query}")
print(f"\nTime range: -1h")
print("\nExecuting...")

events = splunk.query(query, earliest_time="-1h", max_results=5)

print(f"\n✓ Retrieved {len(events)} events")

if events:
    print("\nFirst event sample:")
    for key, value in list(events[0].items())[:10]:
        print(f"  {key}: {value}")
else:
    print("\n⚠ NO EVENTS RETURNED")
    print("\nLet's try a simpler query to see if there's ANY data:")

    simple_query = "search index=zeek_conn | head 5"
    print(f"\nQuery: {simple_query}")

    events = splunk.query(simple_query, earliest_time="-30d", max_results=5)
    print(f"\n✓ Retrieved {len(events)} events")

    if events:
        print("\nFirst event (raw Zeek format):")
        for key, value in list(events[0].items())[:15]:
            print(f"  {key}: {value}")

        print("\n\nAll available fields in first event:")
        for key in sorted(events[0].keys()):
            print(f"  - {key}")
    else:
        print("\n❌ STILL NO DATA - Check:")
        print("  1. Is data actually being ingested into zeek_conn index?")
        print("  2. Is the time range correct?")
        print("  3. Does the token have permissions to read this index?")

print("\n" + "="*80)
print("TESTING DNS QUERIES")
print("="*80)

dns_query = "search index=zeek_dns | head 5"
print(f"\nQuery: {dns_query}")

events = splunk.query(dns_query, earliest_time="-30d", max_results=5)
print(f"\n✓ Retrieved {len(events)} events")

if events:
    print("\nFirst DNS event fields:")
    for key in sorted(events[0].keys())[:20]:
        print(f"  - {key}")

print("\n" + "="*80)
print("TEST COMPLETE")
print("="*80)
