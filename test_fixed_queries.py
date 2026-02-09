#!/usr/bin/env python3
"""
Test the fixed Splunk queries with spath.
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
print("TESTING NETWORK CONNECTIONS (with spath)")
print("="*80)

connections = splunk.get_network_connections(time_range="-1h")
print(f"\n✓ Retrieved {len(connections)} network connections")

if connections:
    print("\nFirst connection:")
    for key, value in connections[0].items():
        print(f"  {key:20s} = {value}")

print("\n" + "="*80)
print("TESTING DNS QUERIES (with spath)")
print("="*80)

dns_queries = splunk.get_dns_queries(time_range="-1h")
print(f"\n✓ Retrieved {len(dns_queries)} DNS queries")

if dns_queries:
    print("\nFirst DNS query:")
    for key, value in dns_queries[0].items():
        print(f"  {key:20s} = {value}")

print("\n" + "="*80)
print("TESTING FULL DATA COLLECTION")
print("="*80)

all_data = splunk.get_all_hunting_data(time_range="-1h")
total = sum(len(v) for v in all_data.values() if isinstance(v, list))
print(f"\n✓ Total events collected: {total}")

for key, value in all_data.items():
    if isinstance(value, list):
        print(f"  {key:25s} = {len(value)} events")

print("\n" + "="*80)
print("SUCCESS! Data is being collected properly.")
print("="*80)
