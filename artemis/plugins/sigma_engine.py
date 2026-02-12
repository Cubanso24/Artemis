"""
Sigma Rule Engine Plugin for Artemis

Loads Sigma detection rules (YAML) and matches them against collected hunting data.
Supports common Sigma detection patterns: field matching, wildcards, modifiers
(|contains, |startswith, |endswith, |re), and basic conditions.
"""

import os
import re
import json
import logging
import fnmatch
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

try:
    import yaml
except ImportError:
    yaml = None

from artemis.plugins import ArtemisPlugin

logger = logging.getLogger("artemis.plugins.sigma")

# Map Sigma logsource categories to Artemis data types
LOGSOURCE_MAP = {
    # Process
    'process_creation': 'process_logs',
    'process_access': 'process_logs',
    'process_termination': 'process_logs',
    # Network
    'network_connection': 'network_connections',
    'firewall': 'network_connections',
    # DNS
    'dns_query': 'dns_queries',
    'dns': 'dns_queries',
    # Auth
    'authentication': 'authentication_logs',
    'logon': 'authentication_logs',
    # PowerShell
    'ps_script': 'powershell_logs',
    'ps_module': 'powershell_logs',
    'ps_classic_start': 'powershell_logs',
    # File
    'file_event': 'file_operations',
    'file_access': 'file_operations',
    'file_change': 'file_operations',
    'file_delete': 'file_operations',
    'file_rename': 'file_operations',
    # Registry
    'registry_event': 'registry_changes',
    'registry_set': 'registry_changes',
    'registry_add': 'registry_changes',
    'registry_delete': 'registry_changes',
    # Scheduled tasks
    'taskscheduler': 'scheduled_tasks',
}


class SigmaRule:
    """Parsed Sigma rule ready for matching."""

    def __init__(self, data: Dict, filepath: str = ""):
        self.raw = data
        self.filepath = filepath
        self.id = data.get('id', '')
        self.title = data.get('title', 'Untitled Rule')
        self.description = data.get('description', '')
        self.status = data.get('status', 'experimental')
        self.level = data.get('level', 'medium')
        self.author = data.get('author', '')
        self.references = data.get('references', [])
        self.tags = data.get('tags', [])

        # Parse logsource
        logsource = data.get('logsource', {})
        self.category = logsource.get('category', '')
        self.product = logsource.get('product', '')
        self.service = logsource.get('service', '')

        # Map to Artemis data type
        self.data_type = LOGSOURCE_MAP.get(self.category, '')

        # Parse detection
        self.detection = data.get('detection', {})
        self.condition = self.detection.get('condition', 'selection')

        # Extract MITRE ATT&CK from tags
        self.mitre_tactics = []
        self.mitre_techniques = []
        for tag in self.tags:
            if tag.startswith('attack.t'):
                self.mitre_techniques.append(tag.replace('attack.', '').upper())
            elif tag.startswith('attack.'):
                tactic = tag.replace('attack.', '').replace('_', ' ').title()
                self.mitre_tactics.append(tactic)

    def get_selections(self) -> Dict[str, Any]:
        """Get all named selections from the detection block."""
        selections = {}
        for key, value in self.detection.items():
            if key != 'condition' and key != 'timeframe':
                selections[key] = value
        return selections


def _match_value(event_value: str, sigma_value: str) -> bool:
    """Match a single event value against a Sigma value (supports wildcards)."""
    if event_value is None:
        return False
    ev = str(event_value).lower()
    sv = str(sigma_value).lower()
    if '*' in sv or '?' in sv:
        return fnmatch.fnmatch(ev, sv)
    return ev == sv


def _match_modifier(event_value: str, sigma_value, modifier: str) -> bool:
    """Match using a Sigma modifier (|contains, |startswith, etc.)."""
    if event_value is None:
        return False
    ev = str(event_value).lower()

    values = sigma_value if isinstance(sigma_value, list) else [sigma_value]

    for val in values:
        sv = str(val).lower()
        if modifier == 'contains':
            if sv in ev:
                return True
        elif modifier == 'startswith':
            if ev.startswith(sv):
                return True
        elif modifier == 'endswith':
            if ev.endswith(sv):
                return True
        elif modifier == 'base64offset':
            # Simplified: just check if value appears
            if sv in ev:
                return True
        elif modifier == 're':
            try:
                if re.search(sv, ev, re.IGNORECASE):
                    return True
            except re.error:
                pass
        elif modifier == 'cidr':
            # Simplified CIDR matching
            try:
                import ipaddress
                if ipaddress.ip_address(str(event_value)) in ipaddress.ip_network(str(val), strict=False):
                    return True
            except (ValueError, TypeError):
                pass
        elif modifier == 'all':
            # All values must match - handled at selection level
            pass
    return False


def _match_selection(event: Dict, selection: Dict) -> bool:
    """Check if an event matches a Sigma selection block."""
    if not isinstance(selection, dict):
        return False

    for field_spec, expected in selection.items():
        # Parse field name and modifier: e.g., "CommandLine|contains"
        parts = field_spec.split('|')
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        # Get event value (case-insensitive field lookup)
        event_value = None
        for k, v in event.items():
            if k.lower() == field_name.lower():
                event_value = v
                break

        # Handle 'all' modifier - every value in the list must match
        use_all = 'all' in modifiers
        active_modifiers = [m for m in modifiers if m != 'all']

        if isinstance(expected, list):
            if active_modifiers:
                mod = active_modifiers[0]
                if use_all:
                    # All values must match
                    if not all(_match_modifier(event_value, val, mod) for val in expected):
                        return False
                else:
                    # Any value can match (OR)
                    if not any(_match_modifier(event_value, val, mod) for val in expected):
                        return False
            else:
                if use_all:
                    if not all(_match_value(event_value, val) for val in expected):
                        return False
                else:
                    # OR: any value matches
                    if not any(_match_value(event_value, val) for val in expected):
                        return False
        else:
            if active_modifiers:
                mod = active_modifiers[0]
                if not _match_modifier(event_value, expected, mod):
                    return False
            else:
                if not _match_value(event_value, expected):
                    return False

    return True


def _evaluate_condition(condition: str, selections: Dict[str, Any], event: Dict) -> bool:
    """Evaluate a Sigma condition string against an event."""
    condition = condition.strip()

    # Handle "1 of selection*" / "all of selection*" patterns
    of_match = re.match(r'(1|all|\d+)\s+of\s+(\w+)\*?', condition)
    if of_match:
        count_str, prefix = of_match.groups()
        matching_selections = {k: v for k, v in selections.items() if k.startswith(prefix)}
        matches = sum(1 for v in matching_selections.values() if _match_selection(event, v))

        if count_str == 'all':
            return matches == len(matching_selections)
        elif count_str == '1':
            return matches >= 1
        else:
            return matches >= int(count_str)

    # Handle "1 of them" / "all of them"
    of_them = re.match(r'(1|all|\d+)\s+of\s+them', condition)
    if of_them:
        count_str = of_them.group(1)
        matches = sum(1 for v in selections.values() if isinstance(v, dict) and _match_selection(event, v))
        if count_str == 'all':
            return matches == len(selections)
        elif count_str == '1':
            return matches >= 1
        else:
            return matches >= int(count_str)

    # Handle "selection and not filter" pattern
    and_not = re.match(r'(\w+)\s+and\s+not\s+(\w+)', condition)
    if and_not:
        sel_name, filter_name = and_not.groups()
        sel = selections.get(sel_name, {})
        filt = selections.get(filter_name, {})
        if isinstance(sel, dict) and _match_selection(event, sel):
            if isinstance(filt, dict) and _match_selection(event, filt):
                return False
            return True
        return False

    # Handle "selection1 or selection2"
    or_parts = [p.strip() for p in condition.split(' or ')]
    if len(or_parts) > 1:
        return any(_evaluate_condition(part, selections, event) for part in or_parts)

    # Handle "selection1 and selection2"
    and_parts = [p.strip() for p in condition.split(' and ')]
    if len(and_parts) > 1:
        return all(_evaluate_condition(part, selections, event) for part in and_parts)

    # Handle "not selection"
    not_match = re.match(r'not\s+(\w+)', condition)
    if not_match:
        sel_name = not_match.group(1)
        sel = selections.get(sel_name, {})
        return not (isinstance(sel, dict) and _match_selection(event, sel))

    # Simple selection name
    sel = selections.get(condition, {})
    if isinstance(sel, dict):
        return _match_selection(event, sel)
    elif isinstance(sel, list):
        # List of dicts = OR between them
        return any(_match_selection(event, s) for s in sel if isinstance(s, dict))

    return False


class SigmaEnginePlugin(ArtemisPlugin):
    """Sigma Rule Engine - loads and matches Sigma detection rules against hunting data."""

    DESCRIPTION = "Sigma detection rule engine for pattern matching against hunt data"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.rules_dir = Path(config.get('rules_dir', 'sigma_rules'))
        self.rules: List[SigmaRule] = []
        self.last_results: List[Dict] = []
        self.results_file = Path(config.get('results_dir', 'sigma_results')) / 'latest.json'

    def initialize(self):
        """Load all Sigma rules from the rules directory."""
        if yaml is None:
            logger.error("PyYAML not installed. Run: pip install pyyaml")
            return

        self.rules_dir.mkdir(exist_ok=True)
        self.results_file.parent.mkdir(exist_ok=True)
        self._load_rules()
        self.enabled = True
        logger.info(f"Sigma Engine initialized: {len(self.rules)} rules loaded from {self.rules_dir}")

    def _load_rules(self):
        """Scan rules directory and parse all .yml/.yaml files."""
        self.rules = []
        if not self.rules_dir.exists():
            return

        for rule_file in sorted(self.rules_dir.rglob('*.y*ml')):
            try:
                with open(rule_file) as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'detection' in data:
                    rule = SigmaRule(data, str(rule_file))
                    if rule.data_type:  # Only load rules we can map to a data type
                        self.rules.append(rule)
                    else:
                        logger.debug(f"Skipping rule (unmapped logsource): {rule.title} [{rule.category}]")
            except Exception as e:
                logger.warning(f"Failed to parse Sigma rule {rule_file}: {e}")

    def reload_rules(self):
        """Reload rules from disk."""
        self._load_rules()
        logger.info(f"Sigma rules reloaded: {len(self.rules)} rules")

    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Match Sigma rules against hunting data.

        Expected kwargs: All 8 Artemis data types as keyword arguments.
        Returns dict with matches grouped by rule.
        """
        if not self.rules:
            return {'matches': [], 'rules_checked': 0, 'total_matches': 0}

        matches = []
        rules_checked = 0
        total_matches = 0

        for rule in self.rules:
            data_key = rule.data_type
            events = kwargs.get(data_key, [])
            if not events:
                continue

            rules_checked += 1
            selections = rule.get_selections()
            matched_events = []

            for event in events:
                if not isinstance(event, dict):
                    continue
                try:
                    if _evaluate_condition(rule.condition, selections, event):
                        matched_events.append(event)
                        if len(matched_events) >= 100:
                            break  # Cap per rule to avoid flooding
                except Exception:
                    continue

            if matched_events:
                total_matches += len(matched_events)
                matches.append({
                    'rule_id': rule.id,
                    'rule_title': rule.title,
                    'rule_description': rule.description,
                    'level': rule.level,
                    'status': rule.status,
                    'author': rule.author,
                    'mitre_tactics': rule.mitre_tactics,
                    'mitre_techniques': rule.mitre_techniques,
                    'data_type': data_key,
                    'match_count': len(matched_events),
                    'sample_events': matched_events[:5],  # Keep first 5 as samples
                    'filepath': rule.filepath,
                })

        # Sort by level severity
        level_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
        matches.sort(key=lambda m: level_order.get(m['level'], 5))

        self.last_results = matches

        # Save results
        result = {
            'timestamp': datetime.now().isoformat(),
            'rules_checked': rules_checked,
            'total_rules': len(self.rules),
            'total_matches': total_matches,
            'matches': matches,
        }
        try:
            with open(self.results_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Failed to save Sigma results: {e}")

        logger.info(f"Sigma scan: {rules_checked} rules checked, {total_matches} matches across {len(matches)} rules")
        return result

    def get_rules(self) -> List[Dict]:
        """Get list of loaded rules for the UI."""
        return [
            {
                'id': r.id,
                'title': r.title,
                'description': r.description,
                'level': r.level,
                'status': r.status,
                'category': r.category,
                'data_type': r.data_type,
                'mitre_tactics': r.mitre_tactics,
                'mitre_techniques': r.mitre_techniques,
                'author': r.author,
                'filepath': r.filepath,
            }
            for r in self.rules
        ]

    def get_last_results(self) -> Dict:
        """Get results from the most recent scan."""
        if self.results_file.exists():
            try:
                with open(self.results_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return {'matches': [], 'rules_checked': 0, 'total_matches': 0}

    def cleanup(self):
        """Clean up resources."""
        self.enabled = False
        logger.info("Sigma Engine stopped")
