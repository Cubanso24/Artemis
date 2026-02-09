#!/usr/bin/env python3
"""Quick script to check available Splunk indexes."""

import os
import splunklib.client as client

# Get credentials from environment
host = os.environ.get('SPLUNK_HOST', '10.25.11.86')
token = os.environ.get('SPLUNK_TOKEN', 'your-token-here')

print(f"Connecting to Splunk at {host}...")

# Connect
service = client.connect(
    host=host,
    port=8089,
    token=token,
    verify=False
)

print("\n=== Available Indexes ===")
indexes = service.indexes
for index in indexes:
    print(f"  - {index.name}")

# Try to find indexes with data
print("\n=== Checking for data in common index patterns ===")

test_searches = [
    ("All indexes", "search index=* earliest=-1h | stats count by index | sort -count"),
    ("Network data", "search sourcetype=* earliest=-1h | stats count by sourcetype | where sourcetype like \"%conn%\" OR sourcetype like \"%network%\" OR sourcetype like \"%firewall%\" OR sourcetype like \"%zeek%\" OR sourcetype like \"%bro%\""),
    ("DNS data", "search sourcetype=* earliest=-1h | stats count by sourcetype | where sourcetype like \"%dns%\""),
    ("Windows logs", "search sourcetype=* earliest=-1h | stats count by sourcetype | where sourcetype like \"%win%\" OR sourcetype like \"%sysmon%\""),
]

for name, query in test_searches:
    print(f"\n{name}:")
    try:
        job = service.jobs.create(query, earliest_time="-1h", max_count=20)

        # Wait for job
        while not job.is_done():
            import time
            time.sleep(0.2)

        # Get results
        import splunklib.results as results
        count = 0
        for result in results.ResultsReader(job.results()):
            if isinstance(result, dict):
                if 'index' in result:
                    print(f"    {result.get('index')}: {result.get('count')} events")
                elif 'sourcetype' in result:
                    print(f"    {result.get('sourcetype')}: {result.get('count')} events")
                count += 1

        if count == 0:
            print("    (no data found)")
    except Exception as e:
        print(f"    Error: {e}")

print("\n" + "="*60)
print("Done! Use these index/sourcetype names to update splunk_connector.py")
