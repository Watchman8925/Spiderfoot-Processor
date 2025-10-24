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


if __name__ == '__main__':
    unittest.main()
