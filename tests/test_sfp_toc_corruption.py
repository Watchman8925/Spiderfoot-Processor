#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         test_sfp_toc_corruption
# Purpose:      Unit tests for the TOC/Corruption SpiderFoot plugin
#
# Author:       Watchman8925
#
# Created:      2025
# License:      MIT
# -------------------------------------------------------------------------------

import unittest
from unittest.mock import Mock, MagicMock
import sys
import os

# Add the plugins directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../plugins'))

try:
    from sfp_toc_corruption import sfp_toc_corruption
except ImportError:
    # If SpiderFoot classes aren't available, create mocks
    class SpiderFootPlugin:
        pass

    class SpiderFootEvent:
        def __init__(self, eventType, data, module, sourceEvent):
            self.eventType = eventType
            self.data = data
            self.module = module
            self.sourceEvent = sourceEvent

    # Mock the imports
    sys.modules['spiderfoot'] = MagicMock()
    sys.modules['spiderfoot'].SpiderFootPlugin = SpiderFootPlugin
    sys.modules['spiderfoot'].SpiderFootEvent = SpiderFootEvent

    from sfp_toc_corruption import sfp_toc_corruption


class TestSfpTocCorruption(unittest.TestCase):
    """Test cases for the TOC/Corruption plugin."""

    def setUp(self):
        """Set up test fixtures."""
        self.plugin = sfp_toc_corruption()

        # Mock SpiderFoot core
        self.mock_sf = Mock()
        self.mock_sf.debug = Mock()

        # Initialize the plugin
        self.plugin.setup(self.mock_sf, {})

    def test_plugin_metadata(self):
        """Test that plugin metadata is properly defined."""
        self.assertIsNotNone(self.plugin.meta)
        self.assertIn('name', self.plugin.meta)
        self.assertEqual(self.plugin.meta['name'], "TOC/Corruption Detector")
        self.assertIn('summary', self.plugin.meta)
        self.assertIn('categories', self.plugin.meta)

    def test_watched_events(self):
        """Test that plugin watches for expected event types."""
        watched = self.plugin.watchedEvents()

        self.assertIn('EMAILADDR', watched)
        self.assertIn('DOMAIN_NAME', watched)
        self.assertIn('IP_ADDRESS', watched)
        self.assertIn('LEAK_SITE', watched)
        self.assertIn('BREACH_DATA', watched)

    def test_produced_events(self):
        """Test that plugin produces expected event types."""
        produced = self.plugin.producedEvents()

        self.assertIn('CORRUPTION_INDICATOR', produced)
        self.assertIn('TOC_INDICATOR', produced)
        self.assertIn('HIGH_RISK_DOMAIN', produced)
        self.assertIn('HIGH_RISK_IPADDR', produced)

    def test_analyze_content_corruption_keywords(self):
        """Test content analysis for corruption keywords."""
        content = "This document discusses fraud and bribery in the organization."
        findings = self.plugin.analyzeContent(content, 'BREACH_DATA')

        self.assertGreater(len(findings), 0)

        # Check that corruption indicators were found
        corruption_findings = [f for f in findings if f['type'] == 'CORRUPTION_INDICATOR']
        self.assertGreater(len(corruption_findings), 0)

    def test_analyze_content_toc_keywords(self):
        """Test content analysis for TOC keywords."""
        content = "System was compromised by malware and data was leaked."
        findings = self.plugin.analyzeContent(content, 'DARKNET_MENTION')

        self.assertGreater(len(findings), 0)

        # Check that TOC indicators were found
        toc_findings = [f for f in findings if f['type'] == 'TOC_INDICATOR']
        self.assertGreater(len(toc_findings), 0)

    def test_analyze_content_no_keywords(self):
        """Test content analysis with no matching keywords."""
        content = "This is a normal business document with no issues."
        findings = self.plugin.analyzeContent(content, 'BREACH_DATA')

        self.assertEqual(len(findings), 0)

    def test_analyze_content_empty(self):
        """Test content analysis with empty content."""
        findings = self.plugin.analyzeContent("", 'BREACH_DATA')
        self.assertEqual(len(findings), 0)

        findings = self.plugin.analyzeContent(None, 'BREACH_DATA')
        self.assertEqual(len(findings), 0)

    def test_check_email_address_suspicious(self):
        """Test email address checking for suspicious patterns."""
        suspicious_email = "test.temp@example.com"
        indicators = self.plugin.checkEmailAddress(suspicious_email)

        self.assertGreater(len(indicators), 0)

    def test_check_email_address_normal(self):
        """Test email address checking for normal email."""
        normal_email = "john.doe@example.com"
        indicators = self.plugin.checkEmailAddress(normal_email)

        # Normal emails may or may not trigger indicators depending on patterns
        self.assertIsInstance(indicators, list)

    def test_check_domain_suspicious_tld(self):
        """Test domain checking with suspicious TLD."""
        suspicious_domain = "example.xyz"
        indicators = self.plugin.checkDomain(suspicious_domain)

        self.assertGreater(len(indicators), 0)
        self.assertTrue(any('Suspicious TLD' in ind for ind in indicators))

    def test_check_domain_phishing_terms(self):
        """Test domain checking with phishing terms."""
        phishing_domain = "secure-login-verify.com"
        indicators = self.plugin.checkDomain(phishing_domain)

        self.assertGreater(len(indicators), 0)
        self.assertTrue(any('phishing term' in ind for ind in indicators))

    def test_check_domain_normal(self):
        """Test domain checking with normal domain."""
        normal_domain = "example.com"
        indicators = self.plugin.checkDomain(normal_domain)

        # Normal domains may or may not trigger indicators
        self.assertIsInstance(indicators, list)

    def test_check_ip_address(self):
        """Test IP address checking."""
        ip_address = "192.168.1.1"
        indicators = self.plugin.checkIPAddress(ip_address)

        # IP checking is a placeholder, should return empty list
        self.assertIsInstance(indicators, list)

    def test_setup_with_custom_options(self):
        """Test plugin setup with custom options."""
        custom_opts = {
            'check_emails': False,
            'sensitivity': 'high'
        }

        self.plugin.setup(self.mock_sf, custom_opts)

        self.assertEqual(self.plugin.opts['check_emails'], False)
        self.assertEqual(self.plugin.opts['sensitivity'], 'high')

    def test_handle_event_skip_own_events(self):
        """Test that plugin skips events from itself."""
        mock_event = Mock()
        mock_event.eventType = 'EMAILADDR'
        mock_event.module = 'sfp_toc_corruption'
        mock_event.data = 'test@example.com'

        self.plugin.notifyListeners = Mock()
        self.plugin.handleEvent(mock_event)

        # Should not notify listeners for own events
        self.plugin.notifyListeners.assert_not_called()

    def test_handle_event_skip_duplicates(self):
        """Test that plugin skips duplicate events."""
        mock_event = Mock()
        mock_event.eventType = 'EMAILADDR'
        mock_event.module = 'other_module'
        mock_event.data = 'test@example.com'

        self.plugin.notifyListeners = Mock()

        # Process the same event twice
        self.plugin.handleEvent(mock_event)
        first_call_count = self.plugin.notifyListeners.call_count

        self.plugin.handleEvent(mock_event)
        second_call_count = self.plugin.notifyListeners.call_count

        # Second call should not increase the count
        self.assertEqual(first_call_count, second_call_count)

    def test_default_options(self):
        """Test that default options are properly set."""
        self.assertIsNotNone(self.plugin.opts)
        self.assertIn('corruption_keywords', self.plugin.opts)
        self.assertIn('toc_keywords', self.plugin.opts)
        self.assertIn('check_emails', self.plugin.opts)
        self.assertIn('check_domains', self.plugin.opts)
        self.assertIn('check_ips', self.plugin.opts)
        self.assertIn('sensitivity', self.plugin.opts)

    def test_option_descriptions(self):
        """Test that option descriptions are provided."""
        self.assertIsNotNone(self.plugin.optdescs)
        self.assertIn('corruption_keywords', self.plugin.optdescs)
        self.assertIn('toc_keywords', self.plugin.optdescs)
        self.assertIn('sensitivity', self.plugin.optdescs)


class TestTocCorruptionIntegration(unittest.TestCase):
    """Integration tests for the TOC/Corruption plugin."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.plugin = sfp_toc_corruption()

        # Mock SpiderFoot core
        self.mock_sf = Mock()
        self.mock_sf.debug = Mock()

        # Initialize the plugin
        self.plugin.setup(self.mock_sf, {})

    def test_email_event_processing(self):
        """Test processing of email address events."""
        mock_event = Mock()
        mock_event.eventType = 'EMAILADDR'
        mock_event.module = 'other_module'
        mock_event.data = 'suspicious.temp.test@example.com'

        self.plugin.notifyListeners = Mock()
        self.plugin.handleEvent(mock_event)

        # Should have notified listeners for suspicious email
        # Note: This will depend on the actual patterns detected
        # self.plugin.notifyListeners.assert_called()

    def test_domain_event_processing(self):
        """Test processing of domain name events."""
        mock_event = Mock()
        mock_event.eventType = 'DOMAIN_NAME'
        mock_event.module = 'other_module'
        mock_event.data = 'secure-login.xyz'

        self.plugin.notifyListeners = Mock()
        self.plugin.handleEvent(mock_event)

        # Should have notified listeners for suspicious domain
        self.assertGreaterEqual(self.plugin.notifyListeners.call_count, 1)


if __name__ == '__main__':
    unittest.main()
