#!/usr/bin/env python3
"""
Discover what indexes and data types are available in your Splunk instance.
"""

import os
from artemis.integrations.splunk_connector import SplunkConnector

def discover_indexes(splunk):
    """Discover available indexes in Splunk."""
    print("=" * 80)
    print("DISCOVERING SPLUNK INDEXES")
    print("=" * 80)

    query = "| eventcount summarize=false index=* | dedup index | table index"
    results = splunk.query(query, earliest_time="-24h", max_results=1000)

    indexes = [r.get('index') for r in results if r.get('index')]

    print(f"\nFound {len(indexes)} indexes:")
    for idx in sorted(indexes):
        print(f"  - {idx}")

    return indexes


def discover_sourcetypes(splunk):
    """Discover available sourcetypes."""
    print("\n" + "=" * 80)
    print("DISCOVERING SOURCETYPES")
    print("=" * 80)

    query = "| metadata type=sourcetypes | table sourcetype"
    results = splunk.query(query, earliest_time="-24h", max_results=1000)

    sourcetypes = [r.get('sourcetype') for r in results if r.get('sourcetype')]

    print(f"\nFound {len(sourcetypes)} sourcetypes:")
    for st in sorted(sourcetypes)[:50]:  # Show first 50
        print(f"  - {st}")

    if len(sourcetypes) > 50:
        print(f"  ... and {len(sourcetypes) - 50} more")

    return sourcetypes


def test_network_data(splunk, indexes):
    """Test which indexes contain network connection data."""
    print("\n" + "=" * 80)
    print("TESTING FOR NETWORK CONNECTION DATA")
    print("=" * 80)

    # Common field names for network connections
    network_fields = [
        'src_ip', 'dest_ip', 'source_ip', 'destination_ip',
        'src', 'dest', 'c_ip', 's_ip'
    ]

    for index in indexes[:20]:  # Test first 20 indexes
        for field in network_fields:
            query = f'search index={index} {field}=* | head 1'
            results = splunk.query(query, earliest_time="-1h", max_results=1)

            if results:
                print(f"\n✓ Found network data in index='{index}' with field '{field}'")

                # Get sample event
                sample_query = f'search index={index} | head 1 | table *'
                sample = splunk.query(sample_query, earliest_time="-1h", max_results=1)

                if sample:
                    print(f"  Sample fields: {', '.join(list(sample[0].keys())[:15])}")
                break


def test_zeek_bro_data(splunk):
    """Test for Zeek/Bro logs specifically."""
    print("\n" + "=" * 80)
    print("TESTING FOR ZEEK/BRO DATA")
    print("=" * 80)

    # Test for Zeek connection logs
    zeek_queries = [
        ('sourcetype=bro:conn:json', 'Zeek conn logs (JSON)'),
        ('sourcetype=zeek:conn:json', 'Zeek conn logs (JSON, newer)'),
        ('sourcetype=bro_conn', 'Zeek conn logs (TSV)'),
        ('sourcetype=bro:conn', 'Zeek conn logs'),
        ('index=zeek', 'Zeek index'),
        ('index=bro', 'Bro index'),
    ]

    for search, description in zeek_queries:
        query = f'search {search} | head 1'
        results = splunk.query(query, earliest_time="-1h", max_results=1)

        if results:
            print(f"\n✓ Found: {description}")
            print(f"  Search: {search}")
            print(f"  Fields: {', '.join(list(results[0].keys())[:15])}")


def test_firewall_data(splunk):
    """Test for firewall logs."""
    print("\n" + "=" * 80)
    print("TESTING FOR FIREWALL DATA")
    print("=" * 80)

    firewall_queries = [
        ('index=firewall', 'Firewall index'),
        ('sourcetype=firewall', 'Firewall sourcetype'),
        ('sourcetype=palo:traffic', 'Palo Alto traffic'),
        ('sourcetype=cisco:asa', 'Cisco ASA'),
        ('sourcetype=fortinet', 'Fortinet'),
    ]

    for search, description in firewall_queries:
        query = f'search {search} | head 1'
        results = splunk.query(query, earliest_time="-1h", max_results=1)

        if results:
            print(f"\n✓ Found: {description}")
            print(f"  Search: {search}")


def main():
    print("Splunk Data Discovery Tool")
    print("This will help identify what data is available for Artemis\n")

    # Get Splunk credentials from environment
    host = os.getenv('SPLUNK_HOST', '10.25.11.86')
    token = os.getenv('SPLUNK_TOKEN')
    username = os.getenv('SPLUNK_USERNAME')
    password = os.getenv('SPLUNK_PASSWORD')

    if not token and not (username and password):
        print("ERROR: Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD environment variables")
        return

    # Connect to Splunk
    print(f"Connecting to Splunk at {host}...\n")

    splunk = SplunkConnector(
        host=host,
        port=8089,
        username=username if not token else "",
        password=password if not token else "",
        token=token,
        verify_ssl=False
    )

    # Run discovery
    indexes = discover_indexes(splunk)
    sourcetypes = discover_sourcetypes(splunk)

    test_zeek_bro_data(splunk)
    test_firewall_data(splunk)
    test_network_data(splunk, indexes)

    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print("\nBased on the results above, you should update the Splunk queries in:")
    print("  artemis/integrations/splunk_connector.py")
    print("\nLook for the get_network_connections() method and update the query to match")
    print("your actual index names and field names.")
    print("\nExample:")
    print('  query = "search index=YOUR_INDEX_HERE | table _time src_ip dest_ip ..."')


if __name__ == "__main__":
    main()
