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

from collections import Counter, defaultdict
from typing import Dict, List, Any
from datetime import datetime


class SpiderFootAnalyzer:
    """Analyze SpiderFoot data for patterns, trends, and insights."""

    def __init__(self, data: List[Dict]):
        """
        Initialize the analyzer with data.

        Args:
            data: List of SpiderFoot records (from CSV import)
        """
        self.data = data
        self.analysis_results = {}

    def analyze_event_distribution(self) -> Dict[str, Any]:
        """
        Analyze the distribution of event types.

        Returns:
            Dictionary with event type distribution
        """
        event_types = [row.get('Type', 'UNKNOWN') for row in self.data]
        distribution = Counter(event_types)

        return {
            'total_events': len(event_types),
            'unique_event_types': len(distribution),
            'distribution': dict(distribution),
            'most_common': distribution.most_common(10)
        }

    def analyze_module_activity(self) -> Dict[str, Any]:
        """
        Analyze which modules generated the most events.

        Returns:
            Dictionary with module activity statistics
        """
        modules = [row.get('Module', 'UNKNOWN') for row in self.data]
        activity = Counter(modules)

        return {
            'total_modules': len(activity),
            'distribution': dict(activity),
            'most_active': activity.most_common(10)
        }

    def analyze_corruption_patterns(self) -> Dict[str, Any]:
        """
        Analyze corruption indicator patterns.

        Returns:
            Dictionary with corruption pattern analysis
        """
        corruption_data = [row for row in self.data
                          if row.get('Type') == 'CORRUPTION_INDICATOR']

        if not corruption_data:
            return {
                'total_indicators': 0,
                'patterns': {},
                'keywords_found': []
            }

        # Extract and analyze corruption keywords
        keywords = []
        patterns = defaultdict(int)

        for row in corruption_data:
            data_field = row.get('Data', '')
            # Extract keyword from data field (format: "Corruption keyword detected: keyword")
            if 'keyword detected:' in data_field.lower():
                keyword = data_field.split(':', 1)[1].strip()
                keywords.append(keyword)
                patterns[keyword] += 1

        return {
            'total_indicators': len(corruption_data),
            'unique_keywords': len(set(keywords)),
            'keywords_distribution': dict(patterns),
            'most_common_keywords': Counter(keywords).most_common(10)
        }

    def analyze_toc_patterns(self) -> Dict[str, Any]:
        """
        Analyze threat of compromise patterns.

        Returns:
            Dictionary with TOC pattern analysis
        """
        toc_data = [row for row in self.data
                   if row.get('Type') == 'TOC_INDICATOR']

        if not toc_data:
            return {
                'total_indicators': 0,
                'patterns': {},
                'keywords_found': []
            }

        # Extract and analyze TOC keywords
        keywords = []
        patterns = defaultdict(int)

        for row in toc_data:
            data_field = row.get('Data', '')
            # Extract keyword from data field
            if 'keyword detected:' in data_field.lower():
                keyword = data_field.split(':', 1)[1].strip()
                keywords.append(keyword)
                patterns[keyword] += 1
            elif 'suspicious pattern' in data_field.lower():
                patterns['suspicious_pattern'] += 1
            elif 'suspicious tld' in data_field.lower():
                patterns['suspicious_tld'] += 1
            elif 'phishing term' in data_field.lower():
                patterns['phishing_term'] += 1

        return {
            'total_indicators': len(toc_data),
            'unique_keywords': len(set(keywords)),
            'keywords_distribution': dict(patterns),
            'most_common_keywords': Counter(keywords).most_common(10) if keywords else []
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
        risk_reasons = defaultdict(int)

        for row in risk_domains:
            source = row.get('Source', '')
            data = row.get('Data', '')

            domains.append(source)

            # Categorize risk reasons
            if 'suspicious tld' in data.lower():
                risk_reasons['Suspicious TLD'] += 1
            elif 'phishing term' in data.lower():
                risk_reasons['Phishing Term'] += 1
            else:
                risk_reasons['Other'] += 1

        return {
            'total_risk_domains': len(risk_domains),
            'unique_domains': len(set(domains)),
            'risk_reasons': dict(risk_reasons),
            'domains': list(set(domains))[:50]  # Return up to 50 unique domains
        }

    def analyze_compromised_assets(self) -> Dict[str, Any]:
        """
        Analyze potentially compromised assets.

        Returns:
            Dictionary with compromised asset analysis
        """
        compromised = [row for row in self.data
                      if row.get('Type') in ['COMPROMISED_ASSET', 'MALICIOUS_AFFILIATE']]

        asset_types = defaultdict(int)
        sources = []

        for row in compromised:
            asset_types[row.get('Type', 'UNKNOWN')] += 1
            sources.append(row.get('Source', ''))

        return {
            'total_compromised': len(compromised),
            'by_type': dict(asset_types),
            'unique_sources': len(set(sources)),
            'sources': list(set(sources))[:50]
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

        timeline = defaultdict(int)

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
        return {
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
            'timeline': self.generate_timeline()
        }

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
