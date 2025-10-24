#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for keyword heuristics in SpiderFootAnalyzer."""

import unittest

from processor.analyzer import SpiderFootAnalyzer


class AnalyzerPatternTests(unittest.TestCase):
    """Validate corruption and TOC heuristic detection paths."""

    def test_corruption_keyword_detection_without_explicit_indicator(self):
        data = [
            {
                'Type': 'RAW_DATA',
                'Module': 'sfp_spider',
                'Source': 'investigative_report.pdf',
                'Data': 'Internal memo describing a bribery and embezzlement scheme.',
            }
        ]
        analyzer = SpiderFootAnalyzer(data)
        results = analyzer.analyze_corruption_patterns()

        self.assertEqual(results['total_indicators'], 1)
        self.assertEqual(results['detection_summary']['plugin_events'], 0)
        self.assertEqual(results['detection_summary']['keyword_matches'], 1)
        self.assertTrue(results['detection_summary']['notes'])

        event = results['events'][0]
        self.assertEqual(event['detection_method'], 'Keyword match')
        detected_keywords = {kw.lower() for kw in event.get('matched_keywords', [])}
        self.assertTrue({'bribery', 'embezzlement'} & detected_keywords)

    def test_toc_keyword_detection_without_explicit_indicator(self):
        data = [
            {
                'Type': 'RAW_DATA',
                'Module': 'sfp_spider',
                'Source': 'threat_feed',
                'Data': 'Credential leak observed after ransomware breach of supplier network.',
            }
        ]
        analyzer = SpiderFootAnalyzer(data)
        results = analyzer.analyze_toc_patterns()

        self.assertEqual(results['total_indicators'], 1)
        self.assertEqual(results['detection_summary']['plugin_events'], 0)
        self.assertEqual(results['detection_summary']['keyword_matches'], 1)
        self.assertTrue(results['detection_summary']['notes'])

        event = results['events'][0]
        self.assertEqual(event['detection_method'], 'Keyword match')
        detected_keywords = {kw.lower() for kw in event.get('matched_keywords', [])}
        self.assertTrue({'ransomware', 'breach', 'credential'} & detected_keywords)

    def test_entity_graph_co_occurrence_and_classification(self):
        data = [
            {
                'Type': 'RAW_DATA',
                'Module': 'sfp_dnsresolve',
                'Source': 'scan1',
                'Data': 'Observed domain evil.example linked to ops@evil.example and 10.0.0.5',
            },
            {
                'Type': 'RAW_DATA',
                'Module': 'sfp_whois',
                'Source': 'whois_logs',
                'Data': 'whois lookup returned evil.example with IP 10.0.0.5',
            },
            {
                'Type': 'RAW_DATA',
                'Module': 'sfp_mail',
                'Source': 'mail_dump',
                'Data': 'Message references ops@evil.example and staging.evil.example alongside 10.0.0.5',
            },
        ]

        analyzer = SpiderFootAnalyzer(data)
        graph = analyzer.analyze_entity_graph()

        self.assertEqual(graph['records_with_entities'], 3)
        self.assertGreaterEqual(graph['total_entities'], 4)

        entity_map = graph['entity_map']
        self.assertIn('evil.example', entity_map)
        self.assertIn('ops@evil.example', entity_map)
        self.assertEqual(entity_map['evil.example']['type'], 'domain')
        self.assertEqual(entity_map['ops@evil.example']['type'], 'email')
        self.assertGreaterEqual(entity_map['10.0.0.5']['occurrences'], 2)

        co_occurrence_index = {
            tuple(sorted(pair['entities'])): pair['count']
            for pair in graph['top_pairs']
        }
        self.assertIn(('evil.example', 'ops@evil.example'), co_occurrence_index)
        self.assertGreaterEqual(co_occurrence_index[('evil.example', 'ops@evil.example')], 2)

        related_entities = {
            rel['entity']
            for rel in entity_map['evil.example']['related']
        }
        self.assertIn('10.0.0.5', related_entities)
        self.assertIn('ops@evil.example', related_entities)

        self.assertTrue(graph['clusters'])
        self.assertGreaterEqual(graph['clusters'][0]['size'], 3)


if __name__ == '__main__':
    unittest.main()
