"""
Context assessment module for the meta-learner.

Monitors and analyzes the current network state to provide context
for intelligent agent activation decisions.
"""

from typing import Dict, List, Any
from datetime import datetime
import logging

from artemis.models.network_state import NetworkState, TimeFeatures
from artemis.models.threat_hypothesis import ThreatHypothesis, HypothesisType
from artemis.utils.logging_config import ArtemisLogger


class ContextAssessor:
    """
    Assesses network context and generates threat hypotheses.

    Provides environmental awareness to the meta-learner for
    informed decision-making.
    """

    def __init__(self):
        self.logger = ArtemisLogger.setup_logger("artemis.meta_learner.context")
        self.historical_states: List[NetworkState] = []
        self.max_history = 100

    def assess_context(self, current_data: Dict[str, Any]) -> NetworkState:
        """
        Assess current network context from available data.

        Args:
            current_data: Current network/system data

        Returns:
            NetworkState representing current context
        """
        from artemis.models.network_state import (
            TrafficMetrics,
            AlertHistory,
            ThreatIntelligence,
            AssetContext
        )

        # Create time features
        time_features = TimeFeatures.from_timestamp(datetime.utcnow())

        # Extract traffic metrics
        traffic_metrics = self._extract_traffic_metrics(current_data.get("network_traffic", {}))

        # Extract alert history
        alert_history = self._extract_alert_history(current_data.get("alerts", {}))

        # Extract threat intelligence
        threat_intel = self._extract_threat_intel(current_data.get("threat_intelligence", {}))

        # Extract asset context
        asset_context = self._extract_asset_context(current_data.get("assets", {}))

        # Calculate system load
        system_load = current_data.get("system_load", 0.5)

        # Create network state
        network_state = NetworkState(
            time_features=time_features,
            traffic_metrics=traffic_metrics,
            alert_history=alert_history,
            threat_intel=threat_intel,
            asset_context=asset_context,
            system_load=system_load
        )

        # Store in history
        self._update_history(network_state)

        self.logger.info(f"Context assessed: {network_state.get_context_summary()}")

        return network_state

    def _extract_traffic_metrics(self, traffic_data: Dict) -> 'TrafficMetrics':
        """Extract traffic metrics from data."""
        from artemis.models.network_state import TrafficMetrics

        return TrafficMetrics(
            total_bytes_in=traffic_data.get("bytes_in", 0),
            total_bytes_out=traffic_data.get("bytes_out", 0),
            connection_count=traffic_data.get("connections", 0),
            unique_destinations=traffic_data.get("unique_destinations", 0),
            dns_queries=traffic_data.get("dns_queries", 0),
            failed_connections=traffic_data.get("failed_connections", 0),
            protocol_distribution=traffic_data.get("protocol_distribution", {})
        )

    def _extract_alert_history(self, alert_data: Dict) -> 'AlertHistory':
        """Extract alert history from data."""
        from artemis.models.network_state import AlertHistory

        return AlertHistory(
            total_alerts_24h=alert_data.get("alerts_24h", 0),
            total_alerts_7d=alert_data.get("alerts_7d", 0),
            recent_incident_types=alert_data.get("incident_types", []),
            false_positive_rate=alert_data.get("fp_rate", 0.0),
            mean_time_to_detect=alert_data.get("mttd", 0.0),
            mean_time_to_respond=alert_data.get("mttr", 0.0)
        )

    def _extract_threat_intel(self, intel_data: Dict) -> 'ThreatIntelligence':
        """Extract threat intelligence from data."""
        from artemis.models.network_state import ThreatIntelligence

        return ThreatIntelligence(
            active_campaigns=intel_data.get("campaigns", []),
            industry_threats=intel_data.get("industry_threats", []),
            ioc_matches=intel_data.get("ioc_matches", 0),
            threat_actor_ttps=intel_data.get("threat_actor_ttps", {}),
            risk_score=intel_data.get("risk_score", 0.0)
        )

    def _extract_asset_context(self, asset_data: Dict) -> 'AssetContext':
        """Extract asset context from data."""
        from artemis.models.network_state import AssetContext

        return AssetContext(
            critical_assets=asset_data.get("critical_assets", []),
            high_value_targets=asset_data.get("high_value_targets", []),
            active_users=asset_data.get("active_users", 0),
            privileged_sessions=asset_data.get("privileged_sessions", 0),
            maintenance_windows=asset_data.get("maintenance_windows", []),
            business_critical_systems=asset_data.get("business_critical", [])
        )

    def _update_history(self, state: NetworkState):
        """Update historical state tracking."""
        self.historical_states.append(state)
        if len(self.historical_states) > self.max_history:
            self.historical_states = self.historical_states[-self.max_history:]

    def generate_hypotheses(
        self,
        initial_signals: List[Dict[str, Any]],
        context: NetworkState
    ) -> List[ThreatHypothesis]:
        """
        Generate threat hypotheses based on initial signals and context.

        Args:
            initial_signals: Initial alerts, anomalies, or indicators
            context: Current network state

        Returns:
            List of threat hypotheses
        """
        hypotheses = []

        for signal in initial_signals:
            signal_type = signal.get("type", "")
            confidence = signal.get("confidence", 0.5)

            # Generate hypothesis based on signal type
            if "reconnaissance" in signal_type.lower():
                hypothesis = ThreatHypothesis(
                    hypothesis_id=f"hyp_{datetime.utcnow().timestamp()}",
                    hypothesis_type=HypothesisType.KILL_CHAIN_STAGE,
                    description="Initial reconnaissance activity detected",
                    initial_indicators=[signal_type],
                    suggested_agents=["reconnaissance_hunter", "initial_access_hunter"],
                    priority=0.7,
                    confidence=confidence,
                    kill_chain_stages=["TA0043", "TA0001"]
                )
                hypotheses.append(hypothesis)

            elif "execution" in signal_type.lower():
                hypothesis = ThreatHypothesis(
                    hypothesis_id=f"hyp_{datetime.utcnow().timestamp()}",
                    hypothesis_type=HypothesisType.CHAIN_OF_EVENTS,
                    description="Execution detected, checking for persistence and lateral movement",
                    initial_indicators=[signal_type],
                    suggested_agents=[
                        "execution_persistence_hunter",
                        "credential_access_hunter",
                        "lateral_movement_hunter"
                    ],
                    priority=0.8,
                    confidence=confidence,
                    kill_chain_stages=["TA0002", "TA0003", "TA0006"]
                )
                hypotheses.append(hypothesis)

            elif "credential" in signal_type.lower():
                hypothesis = ThreatHypothesis(
                    hypothesis_id=f"hyp_{datetime.utcnow().timestamp()}",
                    hypothesis_type=HypothesisType.ANOMALY_INVESTIGATION,
                    description="Credential access anomaly detected",
                    initial_indicators=[signal_type],
                    suggested_agents=[
                        "credential_access_hunter",
                        "lateral_movement_hunter",
                        "defense_evasion_hunter"
                    ],
                    priority=0.85,
                    confidence=confidence,
                    kill_chain_stages=["TA0006", "TA0008"]
                )
                hypotheses.append(hypothesis)

            # Check threat intelligence for known campaigns
            if context.threat_intel.active_campaigns:
                hypothesis = ThreatHypothesis(
                    hypothesis_id=f"hyp_{datetime.utcnow().timestamp()}_intel",
                    hypothesis_type=HypothesisType.APT_CAMPAIGN,
                    description=f"Activity matches known campaign: {context.threat_intel.active_campaigns[0]}",
                    initial_indicators=context.threat_intel.active_campaigns,
                    suggested_agents=self._get_agents_for_campaign(context.threat_intel.active_campaigns[0]),
                    priority=0.9,
                    confidence=0.6,
                    threat_actor_profile=context.threat_intel.active_campaigns[0]
                )
                hypotheses.append(hypothesis)

        self.logger.info(f"Generated {len(hypotheses)} threat hypotheses")
        return hypotheses

    def _get_agents_for_campaign(self, campaign: str) -> List[str]:
        """Get recommended agents for a known threat campaign."""
        # Simplified mapping - in production, use threat intel database
        return [
            "reconnaissance_hunter",
            "initial_access_hunter",
            "execution_persistence_hunter",
            "c2_hunter",
            "defense_evasion_hunter"
        ]

    def detect_anomalies(self, current_state: NetworkState) -> List[Dict[str, Any]]:
        """
        Detect anomalies by comparing current state to historical baseline.

        Args:
            current_state: Current network state

        Returns:
            List of detected anomalies
        """
        anomalies = []

        if len(self.historical_states) < 10:
            # Not enough history for anomaly detection
            return anomalies

        # Calculate baselines from history
        avg_alerts = sum(s.alert_history.total_alerts_24h for s in self.historical_states) / len(self.historical_states)
        avg_connections = sum(s.traffic_metrics.connection_count for s in self.historical_states) / len(self.historical_states)

        # Check for alert volume anomaly
        if current_state.alert_history.total_alerts_24h > avg_alerts * 2:
            anomalies.append({
                "type": "alert_volume_spike",
                "description": f"Alert volume {current_state.alert_history.total_alerts_24h} exceeds baseline {avg_alerts:.0f}",
                "severity": "high",
                "confidence": 0.7
            })

        # Check for connection anomaly
        if current_state.traffic_metrics.connection_count > avg_connections * 3:
            anomalies.append({
                "type": "connection_spike",
                "description": f"Connection count {current_state.traffic_metrics.connection_count} exceeds baseline",
                "severity": "medium",
                "confidence": 0.6
            })

        return anomalies
