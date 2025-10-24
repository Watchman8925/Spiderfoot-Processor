#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         analyzer
# Purpose:      Analyze SpiderFoot data for patterns and insights
#
# Author:       Watchman8925
#
# Created:      2025
# License:      MIT
# -------------------------------------------------------------------------------

import re
from collections import Counter, defaultdict, deque
from itertools import combinations
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple
from datetime import datetime


TEXT_FIELDS_TO_SCAN = (
    'Data',
    'Source',
    'Notes',
    'Description',
    'Summary',
    'Detail',
    'Details',
    'Body',
    'Title',
)

CORRUPTION_KEYWORDS = [
    'corruption',
    'bribery',
    'bribe',
    'kickback',
    'embezzlement',
    'fraud',
    'money laundering',
    'money-laundering',
    'nepotism',
    'extortion',
    'graft',
    'illicit payment',
    'payoff',
    'misappropriation',
    'shell company',
    'offshore account',
    'slush fund',
]

TOC_KEYWORDS = [
    'breach',
    'data breach',
    'compromise',
    'compromised',
    'leaked',
    'data leak',
    'exposed',
    'credential',
    'password dump',
    'malware',
    'ransomware',
    'backdoor',
    'exfiltration',
    'phishing',
    'botnet',
    'zero-day',
    'exploit',
    'intrusion',
    'payload',
    'threat actor',
    'attack',
]

DOMAIN_PATTERN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
MAX_ENTITY_SAMPLE_EVENTS = 5
MAX_CLUSTER_SIZE = 25


class SpiderFootAnalyzer:
    """Analyze SpiderFoot data for patterns, trends, and insights."""

    def __init__(self, data: List[Dict]):
        """
        Initialize the analyzer with data.

        Args:
            data: List of SpiderFoot records (from CSV import)
        """
        self.data = data
        self.analysis_results: Dict[str, Any] = {}

    def _normalize_record(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Return a trimmed, presentation-friendly view of a SpiderFoot record."""
        record = {
            'type': row.get('Type', 'UNKNOWN'),
            'module': row.get('Module', 'UNKNOWN'),
            'source': row.get('Source', ''),
            'data': row.get('Data', ''),
            'timestamp': row.get('Time') or row.get('Timestamp') or '',
            'raw': row
        }
        return record

    def _extract_indicator_keyword(self, data_field: Any) -> Optional[str]:
        if not isinstance(data_field, str):
            return None
        lowered = data_field.lower()
        if 'keyword detected:' in lowered:
            return data_field.split(':', 1)[1].strip()
        return None

    def _stringify_value(self, value: Any) -> List[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, (int, float)):
            return [str(value)]
        if isinstance(value, (list, tuple, set)):
            parts: List[str] = []
            for item in value:
                parts.extend(self._stringify_value(item))
            return parts
        if isinstance(value, dict):
            dict_parts: List[str] = []
            for item in value.values():
                dict_parts.extend(self._stringify_value(item))
            return dict_parts
        return []

    def _collect_row_text(self, row: Dict[str, Any]) -> str:
        text_parts: List[str] = []
        for field in TEXT_FIELDS_TO_SCAN:
            text_parts.extend(self._stringify_value(row.get(field)))
        if not text_parts:
            for key, value in row.items():
                if isinstance(key, str) and key.startswith('__'):
                    continue
                text_parts.extend(self._stringify_value(value))
        return " ".join(part for part in text_parts if part)

    def _normalise_keywords(self, keywords: Set[str]) -> List[str]:
        normalised: Dict[str, str] = {}
        for keyword in keywords:
            if not keyword:
                continue
            canonical = keyword.strip()
            if not canonical:
                continue
            key = canonical.lower()
            if key not in normalised:
                normalised[key] = canonical
        return list(normalised.values())

    def _keyword_matches(self, text: str, keywords: List[str]) -> Set[str]:
        matches: Set[str] = set()
        if not text:
            return matches
        lowered = text.lower()
        for keyword in keywords:
            candidate = keyword.lower()
            if ' ' in candidate or '-' in candidate or '/' in candidate:
                if candidate in lowered:
                    matches.add(keyword)
            else:
                if re.search(rf"\b{re.escape(candidate)}\b", lowered):
                    matches.add(keyword)
        return matches

    def _extract_entities_from_text(self, text: str) -> Set[str]:
        if not isinstance(text, str) or not text:
            return set()
        entities: Set[str] = set()
        entities.update(DOMAIN_PATTERN.findall(text))
        entities.update(IP_PATTERN.findall(text))
        entities.update(EMAIL_PATTERN.findall(text))
        return entities

    def _extract_entities_from_row(self, row: Dict[str, Any]) -> Set[str]:
        entities: Set[str] = set()
        entities.update(self._extract_entities_from_text(row.get('Data', '')))
        entities.update(self._extract_entities_from_text(row.get('Source', '')))
        entities.update(self._extract_entities_from_text(self._collect_row_text(row)))
        return entities

    def _classify_entity(self, entity: str) -> str:
        if '@' in entity:
            return 'email'
        if IP_PATTERN.fullmatch(entity or ''):
            return 'ip'
        if DOMAIN_PATTERN.fullmatch(entity or ''):
            return 'domain'
        return 'unknown'

    def _detect_keyword_matches(
        self,
        rows: List[Dict[str, Any]],
        keywords: List[str],
        skip_ids: Optional[Set[int]] = None,
        method_label: str = "Keyword match"
    ) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        active_skip_ids: Set[int] = skip_ids if skip_ids is not None else set()
        for row in rows:
            row_id = id(row)
            if row_id in active_skip_ids:
                continue
            text_blob = self._collect_row_text(row)
            keyword_hits = self._keyword_matches(text_blob, keywords)
            if not keyword_hits:
                continue
            record = self._normalize_record(row)
            normalized_hits = self._normalise_keywords(keyword_hits)
            if normalized_hits:
                record['matched_keywords'] = normalized_hits
            record['detection_method'] = method_label
            matches.append(record)
            active_skip_ids.add(row_id)
        return matches

    def analyze_event_distribution(self) -> Dict[str, Any]:
        """
        Analyze the distribution of event types.

        Returns:
            Dictionary with event type distribution
        """
        event_types: List[str] = []
        records_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for row in self.data:
            event_type = row.get('Type', 'UNKNOWN')
            event_types.append(event_type)
            records_by_type[event_type].append(self._normalize_record(row))

        distribution = Counter(event_types)

        return {
            'total_events': len(event_types),
            'unique_event_types': len(distribution),
            'distribution': dict(distribution),
            'most_common': distribution.most_common(10),
            'records_by_type': {key: value for key, value in records_by_type.items()}
        }

    def analyze_module_activity(self) -> Dict[str, Any]:
        """
        Analyze which modules generated the most events.

        Returns:
            Dictionary with module activity statistics
        """
        modules: List[str] = []
        records_by_module: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for row in self.data:
            module = row.get('Module', 'UNKNOWN')
            modules.append(module)
            records_by_module[module].append(self._normalize_record(row))

        activity = Counter(modules)

        return {
            'total_modules': len(activity),
            'distribution': dict(activity),
            'most_active': activity.most_common(10),
            'records_by_module': {key: value for key, value in records_by_module.items()}
        }

    def analyze_corruption_patterns(self) -> Dict[str, Any]:
        """
        Analyze corruption indicator patterns.

        Returns:
            Dictionary with corruption pattern analysis
        """
        corruption_rows = [row for row in self.data if row.get('Type') == 'CORRUPTION_INDICATOR']

        keyword_counter: Counter[str] = Counter()
        patterns: DefaultDict[str, int] = defaultdict(int)
        events: List[Dict[str, Any]] = []
        summary_notes: List[str] = []
        plugin_events = 0
        keyword_matches = 0
        other_matches = 0
        seen_ids: Set[int] = set()

        for row in corruption_rows:
            seen_ids.add(id(row))
            record = self._normalize_record(row)
            record['detection_method'] = 'Plugin finding'

            matched_keywords: Set[str] = set()
            extracted = self._extract_indicator_keyword(row.get('Data'))
            if extracted:
                matched_keywords.add(extracted)
            matched_keywords.update(self._keyword_matches(self._collect_row_text(row), CORRUPTION_KEYWORDS))

            normalised = self._normalise_keywords(matched_keywords)
            if normalised:
                record['matched_keywords'] = normalised
                for keyword in normalised:
                    keyword_counter[keyword] += 1
                    patterns[keyword] += 1

            events.append(record)

        plugin_events = len(events)

        heuristic_events = self._detect_keyword_matches(
            self.data,
            CORRUPTION_KEYWORDS,
            skip_ids=seen_ids,
            method_label="Keyword match"
        )

        for record in heuristic_events:
            for keyword in record.get('matched_keywords', []):
                keyword_counter[keyword] += 1
                patterns[keyword] += 1

        if heuristic_events:
            keyword_matches = len(heuristic_events)
            summary_notes.append(
                "Keyword heuristics surfaced potential corruption-related records that were not explicitly flagged."
            )

        total_indicators = len(events)

        if plugin_events == 0 and keyword_matches > 0:
            summary_notes.append(
                "No explicit CORRUPTION_INDICATOR events were present; results rely on keyword heuristics."
            )
        if plugin_events == 0 and keyword_matches == 0 and total_indicators == 0:
            summary_notes.append(
                "No corruption indicators were discovered in the dataset."
            )

        events.extend(heuristic_events)

        detection_summary = {
            'plugin_events': plugin_events,
            'keyword_matches': keyword_matches,
            'other_matches': other_matches,
            'notes': summary_notes,
        }

        return {
            'total_indicators': len(events),
            'unique_keywords': len(keyword_counter),
            'keywords_distribution': dict(patterns),
            'most_common_keywords': keyword_counter.most_common(10),
            'events': events,
            'detection_summary': detection_summary,
            'patterns': dict(patterns),
            'keywords_found': list(keyword_counter.elements()),
        }

    def analyze_entity_graph(self) -> Dict[str, Any]:
        """Build relationships between domains, IPs, and emails observed in the dataset."""

        entity_stats: Dict[str, Dict[str, Any]] = {}
        pair_counts: Counter[Tuple[str, str]] = Counter()
        total_records_with_entities = 0

        for row in self.data:
            entities = sorted(self._extract_entities_from_row(row))
            if not entities:
                continue

            total_records_with_entities += 1
            record = self._normalize_record(row)

            for entity in entities:
                stats = entity_stats.setdefault(
                    entity,
                    {
                        'type': self._classify_entity(entity),
                        'occurrences': 0,
                        'modules': set(),
                        'sources': set(),
                        'related': defaultdict(int),
                        'samples': [],
                    },
                )
                stats['occurrences'] += 1
                if record['module']:
                    stats['modules'].add(record['module'])
                if record['source']:
                    stats['sources'].add(record['source'])
                if len(stats['samples']) < MAX_ENTITY_SAMPLE_EVENTS:
                    stats['samples'].append(record)

            for left, right in combinations(entities, 2):
                left_entity, right_entity = sorted((left, right))
                pair: Tuple[str, str] = (left_entity, right_entity)
                pair_counts[pair] += 1
                entity_stats[left]['related'][right] += 1
                entity_stats[right]['related'][left] += 1

        if not entity_stats:
            return {
                'total_entities': 0,
                'records_with_entities': 0,
                'top_entities': [],
                'top_pairs': [],
                'clusters': [],
                'entity_map': {},
                'type_breakdown': {},
                'notes': ['No domains, IPs, or email addresses were detected in the uploaded dataset.'],
            }

        def _sorted_related(related: Dict[str, int]) -> List[Dict[str, Any]]:
            return [
                {
                    'entity': other,
                    'count': count,
                }
                for other, count in sorted(related.items(), key=lambda item: item[1], reverse=True)
            ]

        entity_map: Dict[str, Dict[str, Any]] = {}
        type_counter: Counter[str] = Counter()
        orphan_entities = 0

        for entity, stats in entity_stats.items():
            related = stats['related']
            type_counter[stats['type']] += 1
            if not related:
                orphan_entities += 1

            entity_map[entity] = {
                'type': stats['type'],
                'occurrences': stats['occurrences'],
                'modules': sorted(stats['modules']),
                'sources': sorted(stats['sources']),
                'related': _sorted_related(related),
                'samples': stats['samples'],
                'degree': len(related),
            }

        top_entities = [
            {
                'entity': entity,
                'type': data['type'],
                'occurrences': data['occurrences'],
                'degree': data['degree'],
                'modules': data['modules'],
            }
            for entity, data in sorted(
                entity_map.items(),
                key=lambda item: (item[1]['occurrences'], item[1]['degree']),
                reverse=True,
            )[:15]
        ]

        top_pairs = []
        for (left, right), count in pair_counts.most_common(20):
            left_modules = set(entity_map[left]['modules'])
            right_modules = set(entity_map[right]['modules'])
            shared_modules = sorted(left_modules.intersection(right_modules))
            top_pairs.append(
                {
                    'entities': [left, right],
                    'count': count,
                    'shared_modules': shared_modules,
                }
            )

        clusters = self._build_entity_clusters(entity_stats)

        notes: List[str] = []
        if orphan_entities:
            notes.append(
                f"{orphan_entities} entity(ies) were observed only once without any linked peers."
            )
        if not pair_counts:
            notes.append("No co-occurring entity pairs were identified across the dataset.")

        return {
            'total_entities': len(entity_stats),
            'records_with_entities': total_records_with_entities,
            'top_entities': top_entities,
            'top_pairs': top_pairs,
            'clusters': clusters,
            'entity_map': entity_map,
            'type_breakdown': dict(type_counter),
            'notes': notes,
        }

    def _build_entity_clusters(self, entity_stats: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not entity_stats:
            return []

        adjacency: Dict[str, Set[str]] = {
            entity: set(stats['related'].keys())
            for entity, stats in entity_stats.items()
        }

        visited: Set[str] = set()
        clusters: List[Dict[str, Any]] = []

        for entity in adjacency:
            if entity in visited:
                continue

            queue: deque[str] = deque([entity])
            component: List[str] = []
            total_occurrences = 0

            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)
                total_occurrences += entity_stats[current]['occurrences']
                for neighbour in adjacency[current]:
                    if neighbour not in visited:
                        queue.append(neighbour)

            component_sorted = sorted(
                component,
                key=lambda node: entity_stats[node]['occurrences'],
                reverse=True,
            )
            clusters.append(
                {
                    'size': len(component),
                    'total_occurrences': total_occurrences,
                    'entities': component_sorted[:MAX_CLUSTER_SIZE],
                }
            )

        clusters.sort(key=lambda item: (item['size'], item['total_occurrences']), reverse=True)
        return clusters[:10]

    def analyze_toc_patterns(self) -> Dict[str, Any]:
        """
        Analyze threat of compromise patterns.

        Returns:
            Dictionary with TOC pattern analysis
        """
        toc_rows = [row for row in self.data if row.get('Type') == 'TOC_INDICATOR']

        keyword_counter: Counter[str] = Counter()
        patterns: DefaultDict[str, int] = defaultdict(int)
        events: List[Dict[str, Any]] = []
        summary_notes: List[str] = []
        plugin_events = 0
        keyword_matches = 0
        other_matches = 0
        seen_ids: Set[int] = set()

        for row in toc_rows:
            seen_ids.add(id(row))
            record = self._normalize_record(row)
            record['detection_method'] = 'Plugin finding'

            matched_keywords: Set[str] = set()
            extracted = self._extract_indicator_keyword(row.get('Data'))
            if extracted:
                matched_keywords.add(extracted)
            matched_keywords.update(self._keyword_matches(self._collect_row_text(row), TOC_KEYWORDS))

            normalised = self._normalise_keywords(matched_keywords)
            if normalised:
                record['matched_keywords'] = normalised
                for keyword in normalised:
                    keyword_counter[keyword] += 1
                    patterns[keyword] += 1

            data_field = row.get('Data', '')
            if isinstance(data_field, str):
                lowered = data_field.lower()
                if 'suspicious pattern' in lowered:
                    patterns['suspicious_pattern'] += 1
                if 'suspicious tld' in lowered:
                    patterns['suspicious_tld'] += 1
                if 'phishing term' in lowered:
                    patterns['phishing_term'] += 1

            events.append(record)

        plugin_events = len(events)

        heuristic_events = self._detect_keyword_matches(
            self.data,
            TOC_KEYWORDS,
            skip_ids=seen_ids,
            method_label="Keyword match"
        )

        for record in heuristic_events:
            for keyword in record.get('matched_keywords', []):
                keyword_counter[keyword] += 1
                patterns[keyword] += 1

        if heuristic_events:
            keyword_matches = len(heuristic_events)
            summary_notes.append(
                "Keyword heuristics identified potential threat-of-compromise signals beyond explicit plugin findings."
            )

        total_indicators = len(events)

        if plugin_events == 0 and keyword_matches > 0:
            summary_notes.append(
                "No explicit TOC_INDICATOR events were present; results rely on keyword heuristics."
            )

        if plugin_events == 0 and keyword_matches == 0 and total_indicators == 0:
            summary_notes.append(
                "No threat-of-compromise indicators were discovered in the dataset."
            )

        if any(key in patterns for key in ('suspicious_pattern', 'suspicious_tld', 'phishing_term')):
            context_notes = []
            for label in ('suspicious_pattern', 'suspicious_tld', 'phishing_term'):
                if label in patterns:
                    context_notes.append(f"{label.replace('_', ' ').title()} ({patterns[label]})")
                    other_matches += patterns[label]
            if context_notes:
                summary_notes.append(
                    "Additional heuristic signals: " + ', '.join(context_notes)
                )

        events.extend(heuristic_events)

        detection_summary = {
            'plugin_events': plugin_events,
            'keyword_matches': keyword_matches,
            'other_matches': other_matches,
            'notes': summary_notes,
        }

        return {
            'total_indicators': len(events),
            'unique_keywords': len(keyword_counter),
            'keywords_distribution': dict(patterns),
            'most_common_keywords': keyword_counter.most_common(10) if keyword_counter else [],
            'events': events,
            'detection_summary': detection_summary,
            'patterns': dict(patterns),
            'keywords_found': list(keyword_counter.elements()),
        }

    def analyze_risk_domains(self) -> Dict[str, Any]:
        """
        Analyze high-risk domains identified.

        Returns:
            Dictionary with high-risk domain analysis
        """
        risk_domains = [row for row in self.data
                       if row.get('Type') == 'HIGH_RISK_DOMAIN']

        domains = []
        risk_reasons: DefaultDict[str, int] = defaultdict(int)
        domain_details: Dict[str, Dict[str, Any]] = {}
        records: List[Dict[str, Any]] = []

        for row in risk_domains:
            source = row.get('Source', '')
            data = row.get('Data', '')
            module = row.get('Module', '')

            domains.append(source)
            records.append(self._normalize_record(row))

            domain_key = source or data or "UNKNOWN_DOMAIN"
            details = domain_details.setdefault(
                domain_key,
                {
                    'occurrences': 0,
                    'reasons': defaultdict(int),
                    'modules': set(),
                    'examples': [],
                }
            )

            details['occurrences'] += 1
            if module:
                details['modules'].add(module)

            snippet = data.strip()
            if snippet:
                if len(snippet) > 240:
                    snippet = snippet[:237] + '...'
                details['examples'].append(snippet)

            # Categorize risk reasons
            if 'suspicious tld' in data.lower():
                risk_reasons['Suspicious TLD'] += 1
                details['reasons']['Suspicious TLD'] += 1
            elif 'phishing term' in data.lower():
                risk_reasons['Phishing Term'] += 1
                details['reasons']['Phishing Term'] += 1
            else:
                risk_reasons['Other'] += 1
                details['reasons']['Other'] += 1

        return {
            'total_risk_domains': len(risk_domains),
            'unique_domains': len(set(domains)),
            'risk_reasons': dict(risk_reasons),
            'domains': list(set(domains))[:50],  # Return up to 50 unique domains
            'domain_details': {
                domain: {
                    'occurrences': details['occurrences'],
                    'reasons': dict(details['reasons']),
                    'modules': sorted(details['modules']),
                    'examples': details['examples'][:5],
                }
                for domain, details in domain_details.items()
            },
            'records': records
        }

    def analyze_compromised_assets(self) -> Dict[str, Any]:
        """
        Analyze potentially compromised assets.

        Returns:
            Dictionary with compromised asset analysis
        """
        compromised = [row for row in self.data
                      if row.get('Type') in ['COMPROMISED_ASSET', 'MALICIOUS_AFFILIATE']]

        asset_types: DefaultDict[str, int] = defaultdict(int)
        sources = []
        asset_details: Dict[str, Dict[str, Any]] = {}
        records: List[Dict[str, Any]] = []

        for row in compromised:
            asset_types[row.get('Type', 'UNKNOWN')] += 1
            sources.append(row.get('Source', ''))
            records.append(self._normalize_record(row))

            asset_label_candidate = row.get('Data') or row.get('Source') or row.get('Type')
            asset_label: str = asset_label_candidate if isinstance(asset_label_candidate, str) and asset_label_candidate else 'UNKNOWN_ASSET'
            detail = asset_details.setdefault(
                asset_label,
                {
                    'type': row.get('Type', 'UNKNOWN'),
                    'occurrences': 0,
                    'modules': set(),
                    'sources': set(),
                    'examples': [],
                }
            )
            detail['occurrences'] += 1
            module = row.get('Module')
            if module:
                detail['modules'].add(module)
            source = row.get('Source')
            if source:
                detail['sources'].add(source)
            data_field = row.get('Data')
            if data_field:
                snippet = data_field.strip()
                if len(snippet) > 240:
                    snippet = snippet[:237] + '...'
                detail['examples'].append(snippet)

        return {
            'total_compromised': len(compromised),
            'by_type': dict(asset_types),
            'unique_sources': len(set(sources)),
            'sources': list(set(sources))[:50],
            'asset_details': {
                label: {
                    'type': info['type'],
                    'occurrences': info['occurrences'],
                    'modules': sorted(info['modules']),
                    'sources': sorted(info['sources']),
                    'examples': info['examples'][:5],
                }
                for label, info in asset_details.items()
            },
            'records': records
        }

    def generate_timeline(self) -> Dict[str, Any]:
        """
        Generate a timeline of events (if timestamp data available).

        Returns:
            Dictionary with timeline data
        """
        # Check if timestamp field exists
        has_timestamp = any('Time' in row or 'Timestamp' in row for row in self.data)

        if not has_timestamp:
            return {
                'has_timeline': False,
                'message': 'No timestamp data available'
            }

        timeline: DefaultDict[str, int] = defaultdict(int)

        for row in self.data:
            timestamp = row.get('Time') or row.get('Timestamp')
            if timestamp:
                # Parse and group by date
                try:
                    # Assuming format like "2025-10-23 10:30:00"
                    date = timestamp.split()[0] if ' ' in timestamp else timestamp
                    timeline[date] += 1
                except Exception:
                    continue

        return {
            'has_timeline': True,
            'events_by_date': dict(sorted(timeline.items())),
            'total_days': len(timeline)
        }

    def generate_full_analysis(self) -> Dict[str, Any]:
        """
        Generate a comprehensive analysis of all data.

        Returns:
            Dictionary with complete analysis results
        """
        results: Dict[str, Any] = {
            'summary': {
                'total_records': len(self.data),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'event_distribution': self.analyze_event_distribution(),
            'module_activity': self.analyze_module_activity(),
            'corruption_patterns': self.analyze_corruption_patterns(),
            'toc_patterns': self.analyze_toc_patterns(),
            'risk_domains': self.analyze_risk_domains(),
            'compromised_assets': self.analyze_compromised_assets(),
            'entity_graph': self.analyze_entity_graph(),
            'timeline': self.generate_timeline()
        }
        source_files = {
            file_name
            for row in self.data
            for file_name in [row.get('__source_file')]
            if isinstance(file_name, str) and file_name
        }
        if source_files:
            results['summary']['source_filename'] = ', '.join(sorted(source_files))
        source_paths = {
            path
            for row in self.data
            for path in [row.get('__source_path')]
            if isinstance(path, str) and path
        }
        if source_paths:
            results['summary']['source_paths'] = list(sorted(source_paths))
        results['pivots_and_leads'] = self.identify_pivots_and_leads(results)
        self.analysis_results = results
        return results

    def identify_pivots_and_leads(
        self,
        analysis_cache: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Derive actionable pivots and leads from the analysis."""
        analysis = analysis_cache or self.analysis_results or {}
        if not analysis:
            analysis = {
                'corruption_patterns': self.analyze_corruption_patterns(),
                'toc_patterns': self.analyze_toc_patterns(),
                'risk_domains': self.analyze_risk_domains(),
                'compromised_assets': self.analyze_compromised_assets(),
                'module_activity': self.analyze_module_activity(),
                'entity_graph': self.analyze_entity_graph(),
            }

        leads: List[Dict[str, Any]] = []

        # High-risk domains pivots
        risk_domains = analysis.get('risk_domains', {})
        domain_details = risk_domains.get('domain_details', {}) or {}
        sorted_domains = sorted(
            domain_details.items(),
            key=lambda item: item[1].get('occurrences', 0),
            reverse=True
        )

        for domain, details in sorted_domains[:8]:
            occurrences = details.get('occurrences', 0)
            if not domain or occurrences == 0:
                continue

            reasons = details.get('reasons', {})
            top_reason = None
            if reasons:
                top_reason = max(reasons.items(), key=lambda item: item[1])[0]

            confidence = 'High' if occurrences >= 3 else 'Medium'
            rationale = (
                f"Flagged {occurrences} time(s) as HIGH_RISK_DOMAIN events"
                f" due to {top_reason or 'multiple risk signals'}."
            )
            if details.get('modules'):
                rationale += f" Seen across modules: {', '.join(details['modules'])}."

            leads.append({
                'title': domain,
                'category': 'High-Risk Domain',
                'indicator': domain,
                'confidence': confidence,
                'summary': (
                    f"Domain {domain} consistently appeared in high-risk domain alerts "
                    f"({occurrences} occurrence{'s' if occurrences != 1 else ''})."
                ),
                'rationale': rationale,
                'recommended_actions': (
                    'Perform takedown review, enrich WHOIS/hosting data, and correlate with campaign infrastructure.'
                ),
                'supporting_evidence': details.get('examples', []),
                'metrics': {
                    'occurrences': occurrences,
                    'primary_reason': top_reason,
                }
            })

        # Infrastructure co-occurrence pivots
        entity_graph = analysis.get('entity_graph', {}) or {}
        entity_map = entity_graph.get('entity_map', {}) or {}
        pair_limit = 0
        for pair in entity_graph.get('top_pairs', []) or []:
            if pair_limit >= 5:
                break
            count = pair.get('count', 0)
            if count < 2:
                continue
            entities = pair.get('entities', []) or []
            if len(entities) != 2:
                continue
            left, right = entities
            left_meta = entity_map.get(left)
            right_meta = entity_map.get(right)
            if not left_meta or not right_meta:
                continue

            shared_modules = pair.get('shared_modules', []) or []
            confidence = 'High' if count >= 3 else 'Medium'
            rationale_parts = [
                f"Observed together {count} time(s) across {len(shared_modules) or 'multiple'} module(s)"
            ]
            if shared_modules:
                rationale_parts.append(f"notably {', '.join(shared_modules[:3])}")

            leads.append({
                'title': f"Linked Entities: {left} ↔ {right}",
                'category': 'Infrastructure Cluster',
                'indicator': f"{left}::{right}",
                'confidence': confidence,
                'summary': (
                    f"Entities {left} and {right} co-occur in {count} record(s), indicating shared infrastructure or coordinated activity."
                ),
                'rationale': '; '.join(rationale_parts) + '.',
                'recommended_actions': (
                    'Map hosting/WHOIS relationships, broaden collection around linked assets, and monitor for campaign-scale operations.'
                ),
                'supporting_evidence': (
                    (left_meta.get('samples', []) or []) + (right_meta.get('samples', []) or [])
                )[:MAX_ENTITY_SAMPLE_EVENTS],
                'metrics': {
                    'pair_count': count,
                    'left_degree': left_meta.get('degree'),
                    'right_degree': right_meta.get('degree'),
                }
            })
            pair_limit += 1

        # Compromised assets pivots
        compromised = analysis.get('compromised_assets', {})
        asset_details = compromised.get('asset_details', {}) or {}
        sorted_assets = sorted(
            asset_details.items(),
            key=lambda item: item[1].get('occurrences', 0),
            reverse=True
        )

        for asset, details in sorted_assets[:6]:
            occurrences = details.get('occurrences', 0)
            if occurrences == 0:
                continue
            confidence = 'High' if occurrences >= 2 else 'Medium'
            modules = details.get('modules', [])
            sources = details.get('sources', [])
            rationale_parts = [
                f"Observed {occurrences} time(s) as {details.get('type', 'indicator')}"
            ]
            if sources:
                rationale_parts.append(f"originating from {', '.join(sources[:3])}")
            if modules:
                rationale_parts.append(f"via modules {', '.join(modules[:3])}")

            leads.append({
                'title': asset,
                'category': 'Compromised Asset',
                'indicator': asset,
                'confidence': confidence,
                'summary': (
                    f"Asset {asset} surfaced as potentially compromised in {occurrences} event(s)."
                ),
                'rationale': '; '.join(rationale_parts) + '.',
                'recommended_actions': (
                    'Validate exposure scope, rotate credentials, and initiate incident response triage.'
                ),
                'supporting_evidence': details.get('examples', []),
                'metrics': {
                    'occurrences': occurrences,
                    'modules': modules,
                }
            })

        # Corruption keyword clusters
        corruption = analysis.get('corruption_patterns', {})
        for keyword, count in (corruption.get('most_common_keywords') or [])[:5]:
            if not keyword:
                continue
            confidence = 'High' if count >= 5 else 'Medium'
            leads.append({
                'title': f"Corruption Keyword: {keyword}",
                'category': 'Corruption Indicator',
                'indicator': keyword,
                'confidence': confidence,
                'summary': (
                    f"Keyword '{keyword}' triggered {count} corruption indicator event(s)."
                ),
                'rationale': (
                    f"Frequent corruption-aligned language suggests thematic clustering around '{keyword}'."
                ),
                'recommended_actions': (
                    'Pivot on entities and documents containing this keyword to map corruption narratives.'
                ),
                'supporting_evidence': [],
                'metrics': {
                    'occurrences': count,
                }
            })

        # Threat-of-compromise keyword clusters
        toc = analysis.get('toc_patterns', {})
        for keyword, count in (toc.get('most_common_keywords') or [])[:5]:
            if not keyword:
                continue
            confidence = 'High' if count >= 5 else 'Medium'
            leads.append({
                'title': f"TOC Keyword: {keyword}",
                'category': 'Threat of Compromise',
                'indicator': keyword,
                'confidence': confidence,
                'summary': (
                    f"Keyword '{keyword}' surfaced in {count} TOC indicator event(s)."
                ),
                'rationale': (
                    f"Consistent TOC keyword usage indicates active compromise or reconnaissance referencing '{keyword}'."
                ),
                'recommended_actions': (
                    'Hunt for linked incidents, align with intrusion sets, and assess defensive posture.'
                ),
                'supporting_evidence': [],
                'metrics': {
                    'occurrences': count,
                }
            })

        return leads

    def get_recommendations(self) -> List[str]:
        """
        Generate recommendations based on analysis.

        Returns:
            List of recommendation strings
        """
        recommendations = []

        # Analyze corruption patterns
        corruption = self.analyze_corruption_patterns()
        if corruption['total_indicators'] > 10:
            recommendations.append(
                f"High number of corruption indicators detected ({corruption['total_indicators']}). "
                "Consider deeper investigation into identified entities."
            )

        # Analyze TOC patterns
        toc = self.analyze_toc_patterns()
        if toc['total_indicators'] > 10:
            recommendations.append(
                f"Significant threat of compromise indicators found ({toc['total_indicators']}). "
                "Immediate security review recommended."
            )

        # Analyze risk domains
        domains = self.analyze_risk_domains()
        if domains['total_risk_domains'] > 5:
            recommendations.append(
                f"Multiple high-risk domains identified ({domains['total_risk_domains']}). "
                "Consider blocking or monitoring these domains."
            )

        # Analyze compromised assets
        compromised = self.analyze_compromised_assets()
        if compromised['total_compromised'] > 0:
            recommendations.append(
                f"Potentially compromised assets detected ({compromised['total_compromised']}). "
                "Immediate action required to secure these assets."
            )

        if not recommendations:
            recommendations.append("No significant threats detected. Continue monitoring.")

        return recommendations


def analyze_data(data: List[Dict]) -> Dict[str, Any]:
    """
    Convenience function to analyze SpiderFoot data.

    Args:
        data: List of SpiderFoot records

    Returns:
        Dictionary with analysis results
    """
    analyzer = SpiderFootAnalyzer(data)
    return analyzer.generate_full_analysis()
