#!/usr/bin/env python3
"""
Test Splunk integration for Artemis threat hunting system.
"""

import os
import sys
from artemis.integrations.splunk_connector import SplunkConnector

def test_connection():
    """Test basic Splunk connectivity."""
    print("Testing Splunk connection...")

    # Get credentials from environment
    host = os.getenv('SPLUNK_HOST', '10.25.11.86')
    token = os.getenv('SPLUNK_TOKEN')
    username = os.getenv('SPLUNK_USERNAME')
    password = os.getenv('SPLUNK_PASSWORD')

    if not token and not (username and password):
        print("✗ ERROR: Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD")
        return None

    try:
        splunk = SplunkConnector(
            host=host,
            port=8089,
            username=username if not token else "",
            password=password if not token else "",
            token=token,
            verify_ssl=False
        )
        print("✓ Connected to Splunk successfully")
        return splunk
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        return None


def test_query(splunk):
    """Test basic query execution."""
    print("\nRunning test query...")

    try:
        query = "search index=* | head 10"
        results = splunk.query(query, earliest_time="-1h")
        print(f"✓ Query successful - Retrieved {len(results)} events")
        return True
    except Exception as e:
        print(f"✗ Query failed: {e}")
        return False


def test_data_collection(splunk):
    """Test all data collection methods."""
    print("\nTesting data collection...")

    tests = [
        ("DNS queries", lambda: splunk.get_dns_queries("-1h")),
        ("Network connections", lambda: splunk.get_network_connections("-1h")),
        ("Authentication logs", lambda: splunk.get_authentication_logs("-1h")),
        ("Process logs", lambda: splunk.get_process_logs("-1h")),
        ("PowerShell logs", lambda: splunk.get_powershell_logs("-1h")),
        ("File operations", lambda: splunk.get_file_operations("-1h")),
        ("Scheduled tasks", lambda: splunk.get_scheduled_tasks("-1h")),
        ("Registry changes", lambda: splunk.get_registry_changes("-1h")),
    ]

    results = {}
    for name, func in tests:
        try:
            data = func()
            results[name] = len(data)
            print(f"✓ {name}: {len(data)} events")
        except Exception as e:
            results[name] = 0
            print(f"✗ {name}: Error - {e}")

    return results


def test_comprehensive_collection(splunk):
    """Test comprehensive data collection."""
    print("\nTesting comprehensive data collection...")

    try:
        all_data = splunk.get_all_hunting_data("-1h")

        print("\nData Summary:")
        print("=" * 60)
        total_events = 0
        for data_type, events in all_data.items():
            count = len(events)
            total_events += count
            print(f"  {data_type:25s}: {count:6d} events")
        print("=" * 60)
        print(f"  {'TOTAL':25s}: {total_events:6d} events")

        return total_events > 0
    except Exception as e:
        print(f"✗ Comprehensive collection failed: {e}")
        return False


def main():
    print("=" * 60)
    print("ARTEMIS SPLUNK INTEGRATION TEST")
    print("=" * 60)

    # Test connection
    splunk = test_connection()
    if not splunk:
        print("\n✗✗✗ Connection test failed - stopping ✗✗✗")
        sys.exit(1)

    # Test basic query
    if not test_query(splunk):
        print("\n✗✗✗ Query test failed - stopping ✗✗✗")
        sys.exit(1)

    # Test data collection
    results = test_data_collection(splunk)

    # Test comprehensive collection
    success = test_comprehensive_collection(splunk)

    # Summary
    print("\n" + "=" * 60)
    if success and sum(results.values()) > 0:
        print("√√√ Splunk integration is working! √√√")
        print("\nYou're ready to start hunting with Artemis!")
        print("\nNext steps:")
        print("  1. Review the data counts above")
        print("  2. Run your first hunt: python -m artemis.examples.production_deployment")
        print("  3. Check the documentation in docs/DEPLOYMENT.md")
    else:
        print("!!! Some data sources returned no results !!!")
        print("\nThis might be normal if:")
        print("  - The time range (-1h) has no activity")
        print("  - Certain log sources aren't configured")
        print("  - Field names differ from expectations")
        print("\nRun discover_splunk_data.py to investigate further.")
    print("=" * 60)


if __name__ == "__main__":
    main()
