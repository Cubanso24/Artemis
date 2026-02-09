#!/usr/bin/env python3
"""
Artemis Bulk Hunter - Process historical data in time windows
Optimized for analyzing weeks of data to find threats and build baselines.
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

from artemis.meta_learner.coordinator import MetaLearnerCoordinator
from artemis.integrations.data_pipeline import DataPipeline, DataSourceConfig
from artemis.models.network_state import NetworkState


class BulkHuntManager:
    """Manages bulk hunting across historical time windows."""

    def __init__(self, output_dir: str = "bulk_hunt_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.coordinator = MetaLearnerCoordinator()
        self.pipeline = None

        # Tracking metrics
        self.stats = {
            "total_windows": 0,
            "total_findings": 0,
            "total_events_processed": 0,
            "high_risk_windows": [],
            "baseline_metrics": defaultdict(list)
        }

    def initialize_pipeline(self):
        """Initialize data pipeline with Splunk."""
        host = os.getenv('SPLUNK_HOST', '10.25.11.86')
        token = os.getenv('SPLUNK_TOKEN')
        username = os.getenv('SPLUNK_USERNAME')
        password = os.getenv('SPLUNK_PASSWORD')

        if not token and not (username and password):
            print("❌ ERROR: Splunk credentials not set!")
            sys.exit(1)

        config = DataSourceConfig(
            splunk_host=host,
            splunk_port=8089,
            splunk_token=token if token else "",
            splunk_username=username if username else "",
            splunk_password=password if password else ""
        )

        self.pipeline = DataPipeline(config)

    def generate_time_windows(self, days_back: int, window_hours: int):
        """
        Generate time windows for bulk hunting.

        Args:
            days_back: How many days to go back
            window_hours: Size of each hunting window

        Returns:
            List of (start_time, end_time) tuples in Splunk format
        """
        windows = []
        now = datetime.now()

        # Start from days_back ago
        current = now - timedelta(days=days_back)

        while current < now:
            window_end = current + timedelta(hours=window_hours)
            if window_end > now:
                window_end = now

            # Splunk time format
            start_str = f"{int(current.timestamp())}"
            end_str = f"{int(window_end.timestamp())}"

            windows.append({
                'start': start_str,
                'end': end_str,
                'start_dt': current,
                'end_dt': window_end,
                'label': current.strftime("%Y-%m-%d %H:%M")
            })

            current = window_end

        return windows

    def hunt_window(self, window: dict, mode: str = "PARALLEL"):
        """
        Hunt a single time window.

        Args:
            window: Dict with start, end, start_dt, end_dt, label
            mode: Hunting mode (PARALLEL, SEQUENTIAL, ADAPTIVE)

        Returns:
            Hunt results dict
        """
        print(f"\n🔍 Hunting window: {window['label']}")
        print(f"   Time range: {window['start_dt'].strftime('%Y-%m-%d %H:%M')} to {window['end_dt'].strftime('%Y-%m-%d %H:%M')}")

        # Construct Splunk time range
        time_range = f"earliest={window['start']} latest={window['end']}"

        try:
            # Collect data
            hunting_data = self.pipeline.splunk_connector.get_all_hunting_data(time_range=time_range)

            total_events = sum(len(v) for v in hunting_data.values())
            print(f"   📊 Collected {total_events} events")

            if total_events == 0:
                print(f"   ⚠️  No data in this window, skipping...")
                return None

            # Create network state
            network_state = NetworkState.from_data(hunting_data)

            # Run hunt
            hunt_result = self.coordinator.hunt(
                network_state=network_state,
                hunting_data=hunting_data,
                mode=mode
            )

            # Add metadata
            hunt_result['window'] = window
            hunt_result['total_events'] = total_events

            # Count findings
            findings_count = sum(
                len(r.findings)
                for r in hunt_result.get('agent_results', {}).values()
            )

            print(f"   ✓ Found {findings_count} potential threats")

            return hunt_result

        except Exception as e:
            print(f"   ❌ Error hunting window: {e}")
            return None

    def save_window_result(self, result: dict):
        """Save individual window result."""
        if not result:
            return

        window_label = result['window']['label'].replace(' ', '_').replace(':', '')
        output_file = self.output_dir / f"window_{window_label}.json"

        # Prepare serializable data
        serializable_result = {
            'window': result['window'],
            'total_events': result['total_events'],
            'findings_count': sum(
                len(r.findings)
                for r in result.get('agent_results', {}).values()
            ),
            'agent_results': {},
            'aggregated_results': result.get('aggregated_results', {})
        }

        # Extract findings
        for agent_name, agent_result in result.get('agent_results', {}).items():
            serializable_result['agent_results'][agent_name] = {
                'findings': [
                    {
                        'title': f.title,
                        'description': f.description,
                        'severity': f.severity.value,
                        'confidence': f.confidence,
                        'mitre_tactics': f.mitre_tactics,
                        'affected_assets': f.affected_assets
                    }
                    for f in agent_result.findings
                ]
            }

        with open(output_file, 'w') as f:
            json.dump(serializable_result, f, indent=2)

    def update_stats(self, result: dict):
        """Update running statistics."""
        if not result:
            return

        self.stats['total_windows'] += 1
        self.stats['total_events_processed'] += result['total_events']

        findings_count = sum(
            len(r.findings)
            for r in result.get('agent_results', {}).values()
        )
        self.stats['total_findings'] += findings_count

        # Track high-risk windows
        if findings_count >= 5:  # Threshold for "high risk"
            self.stats['high_risk_windows'].append({
                'label': result['window']['label'],
                'findings': findings_count,
                'confidence': result.get('aggregated_results', {}).get('overall_confidence', 0)
            })

        # Track baseline metrics
        network_state_data = result.get('network_state', {})
        self.stats['baseline_metrics']['dns_query_rate'].append(
            network_state_data.get('dns_query_rate', 0)
        )
        self.stats['baseline_metrics']['active_connections'].append(
            network_state_data.get('active_connections', 0)
        )

    def generate_summary_report(self):
        """Generate summary report across all windows."""
        print("\n" + "=" * 80)
        print("  BULK HUNT SUMMARY REPORT")
        print("=" * 80)

        print(f"\n📊 Overall Statistics:")
        print(f"  • Time Windows Analyzed: {self.stats['total_windows']}")
        print(f"  • Total Events Processed: {self.stats['total_events_processed']:,}")
        print(f"  • Total Findings: {self.stats['total_findings']}")
        print(f"  • Average Findings per Window: {self.stats['total_findings'] / max(self.stats['total_windows'], 1):.1f}")

        if self.stats['high_risk_windows']:
            print(f"\n🔴 High-Risk Time Windows ({len(self.stats['high_risk_windows'])} found):")
            for window in sorted(self.stats['high_risk_windows'],
                                key=lambda x: x['findings'],
                                reverse=True)[:10]:
                print(f"  • {window['label']:20s} → {window['findings']:3d} findings (conf: {window['confidence']:.2f})")

        # Baseline metrics
        if self.stats['baseline_metrics']['dns_query_rate']:
            dns_rates = self.stats['baseline_metrics']['dns_query_rate']
            print(f"\n📈 Baseline Metrics:")
            print(f"  DNS Query Rate:")
            print(f"    - Average: {sum(dns_rates) / len(dns_rates):.1f} queries/sec")
            print(f"    - Min: {min(dns_rates):.1f}")
            print(f"    - Max: {max(dns_rates):.1f}")

            connections = self.stats['baseline_metrics']['active_connections']
            print(f"  Active Connections:")
            print(f"    - Average: {sum(connections) / len(connections):.0f}")
            print(f"    - Min: {min(connections)}")
            print(f"    - Max: {max(connections)}")

        # Save summary
        summary_file = self.output_dir / "bulk_hunt_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(self.stats, f, indent=2, default=str)

        print(f"\n💾 Detailed summary saved to: {summary_file}")
        print("=" * 80 + "\n")

    def run_bulk_hunt(self, days_back: int, window_hours: int, mode: str = "PARALLEL"):
        """
        Run bulk hunt across historical data.

        Args:
            days_back: Number of days to go back
            window_hours: Size of each time window in hours
            mode: Hunting mode (PARALLEL, SEQUENTIAL, ADAPTIVE)
        """
        print("=" * 80)
        print("  ARTEMIS BULK THREAT HUNT")
        print("=" * 80)
        print(f"\n⚙️  Configuration:")
        print(f"  • Historical Range: {days_back} days")
        print(f"  • Window Size: {window_hours} hours")
        print(f"  • Hunting Mode: {mode}")

        # Initialize
        self.initialize_pipeline()

        # Generate time windows
        windows = self.generate_time_windows(days_back, window_hours)
        print(f"\n📅 Generated {len(windows)} time windows to hunt")

        # Hunt each window
        print("\n🚀 Starting bulk hunt...\n")
        start_time = time.time()

        for i, window in enumerate(windows, 1):
            print(f"\n[Window {i}/{len(windows)}]", end=" ")

            result = self.hunt_window(window, mode=mode)

            if result:
                self.save_window_result(result)
                self.update_stats(result)

            # Progress update every 10 windows
            if i % 10 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                remaining = (len(windows) - i) / rate
                print(f"\n   ⏱️  Progress: {i}/{len(windows)} windows ({i/len(windows)*100:.0f}%)")
                print(f"   ⏱️  Estimated time remaining: {remaining/60:.0f} minutes")

        # Generate summary
        self.generate_summary_report()

        total_time = time.time() - start_time
        print(f"✅ Bulk hunt completed in {total_time/60:.1f} minutes")
        print(f"📁 Results saved to: {self.output_dir}/")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Artemis Bulk Hunter - Analyze historical data in time windows"
    )
    parser.add_argument(
        '--days',
        type=int,
        default=7,
        help='Number of days to go back (default: 7)'
    )
    parser.add_argument(
        '--window',
        type=int,
        default=6,
        help='Window size in hours (default: 6)'
    )
    parser.add_argument(
        '--mode',
        choices=['PARALLEL', 'SEQUENTIAL', 'ADAPTIVE'],
        default='PARALLEL',
        help='Hunting mode (default: PARALLEL)'
    )

    args = parser.parse_args()

    # Validate
    if args.days < 1:
        print("❌ ERROR: --days must be at least 1")
        sys.exit(1)

    if args.window < 1 or args.window > 24:
        print("❌ ERROR: --window must be between 1 and 24 hours")
        sys.exit(1)

    # Run bulk hunt
    manager = BulkHuntManager()
    manager.run_bulk_hunt(
        days_back=args.days,
        window_hours=args.window,
        mode=args.mode
    )


if __name__ == "__main__":
    main()
