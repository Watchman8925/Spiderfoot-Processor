#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_toc_corruption
# Purpose:      SpiderFoot plug-in for detecting indicators of corruption and
#               threat of compromise (TOC) across various data sources.
#
# Author:       Watchman8925
#
# Created:      2025
# Copyright:    (c) Watchman8925 2025
# License:      MIT
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_toc_corruption(SpiderFootPlugin):
    """TOC/Corruption Detector: Identifies indicators of corruption and threat of compromise."""

    meta = {
        'name': "TOC/Corruption Detector",
        'summary': "Detect indicators of corruption and threat of compromise across various data sources.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://github.com/Watchman8925/Spiderfoot-Processor",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'favIcon': "",
            'logo': "",
            'description': "Analyzes data for indicators of corruption, compromise, and malicious activity."
        }
    }

    opts = {
        'corruption_keywords': ['fraud', 'bribery', 'corruption', 'embezzlement', 'kickback',
                                'money laundering', 'extortion', 'graft'],
        'toc_keywords': ['breach', 'compromise', 'leaked', 'exposed', 'hacked', 'stolen',
                         'malware', 'ransomware', 'backdoor', 'vulnerability'],
        'check_emails': True,
        'check_domains': True,
        'check_ips': True,
        'sensitivity': 'medium'  # low, medium, high
    }

    optdescs = {
        'corruption_keywords': "Keywords that indicate potential corruption. Comma-separated.",
        'toc_keywords': "Keywords that indicate threat of compromise. Comma-separated.",
        'check_emails': "Check email addresses for TOC indicators.",
        'check_domains': "Check domains for TOC indicators.",
        'check_ips': "Check IP addresses for TOC indicators.",
        'sensitivity': "Detection sensitivity level (low, medium, high)."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        """Initialize module and options."""
        self.sf = sfc

        # Use tempStorage if available (from SpiderFootPlugin), otherwise use dict
        if hasattr(self, 'tempStorage'):
            self.results = self.tempStorage()
        else:
            self.results = dict()

        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        """Define event types this module watches for."""
        return [
            'EMAILADDR',
            'DOMAIN_NAME',
            'IP_ADDRESS',
            'AFFILIATE_EMAILADDR',
            'AFFILIATE_DOMAIN_NAME',
            'AFFILIATE_IPADDR',
            'LEAK_SITE',
            'BREACH_DATA',
            'DARKNET_MENTION'
        ]

    def producedEvents(self):
        """Define event types this module produces."""
        return [
            'CORRUPTION_INDICATOR',
            'TOC_INDICATOR',
            'MALICIOUS_AFFILIATE',
            'COMPROMISED_ASSET',
            'HIGH_RISK_DOMAIN',
            'HIGH_RISK_IPADDR'
        ]

    def analyzeContent(self, content, eventType):
        """Analyze content for corruption and TOC indicators."""
        if not content:
            return []

        findings = []
        content_lower = content.lower()

        # Check for corruption keywords
        for keyword in self.opts['corruption_keywords']:
            if keyword.lower() in content_lower:
                findings.append({
                    'type': 'CORRUPTION_INDICATOR',
                    'data': f"Corruption keyword detected: {keyword}",
                    'confidence': 'MEDIUM'
                })

        # Check for TOC keywords
        for keyword in self.opts['toc_keywords']:
            if keyword.lower() in content_lower:
                findings.append({
                    'type': 'TOC_INDICATOR',
                    'data': f"TOC keyword detected: {keyword}",
                    'confidence': 'MEDIUM'
                })

        return findings

    def checkEmailAddress(self, email):
        """Check if email address shows signs of compromise."""
        indicators = []

        # Check for common patterns in compromised emails
        suspicious_patterns = ['temp', 'fake', 'throwaway', 'test', 'spam']

        email_lower = email.lower()
        for pattern in suspicious_patterns:
            if pattern in email_lower:
                indicators.append(f"Suspicious pattern in email: {pattern}")

        return indicators

    def checkDomain(self, domain):
        """Check if domain shows signs of compromise or malicious activity."""
        indicators = []

        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq']

        domain_lower = domain.lower()
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                indicators.append(f"Suspicious TLD: {tld}")

        # Check for typosquatting patterns
        suspicious_terms = ['secure', 'account', 'verify', 'login', 'update']
        for term in suspicious_terms:
            if term in domain_lower:
                indicators.append(f"Potential phishing term: {term}")

        return indicators

    def checkIPAddress(self, ip):
        """Check if IP address shows signs of malicious activity."""
        indicators = []

        # This is a placeholder for IP reputation checks
        # In a real implementation, you would integrate with threat intelligence feeds

        return indicators

    def handleEvent(self, event):
        """Process events received from SpiderFoot core."""
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Don't process events from ourselves
        if srcModuleName == "sfp_toc_corruption":
            return

        if hasattr(self, 'debug'):
            self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Check if we've already processed this data
        if eventData in self.results:
            if hasattr(self, 'debug'):
                self.debug(f"Skipping {eventData}, already processed.")
            return

        self.results[eventData] = True

        findings = []

        # Process based on event type
        if eventName == 'EMAILADDR' and self.opts['check_emails']:
            indicators = self.checkEmailAddress(eventData)
            for indicator in indicators:
                findings.append({
                    'type': 'TOC_INDICATOR',
                    'data': indicator,
                    'source': eventData
                })

        elif eventName in ['DOMAIN_NAME', 'AFFILIATE_DOMAIN_NAME'] and self.opts['check_domains']:
            indicators = self.checkDomain(eventData)
            for indicator in indicators:
                findings.append({
                    'type': 'HIGH_RISK_DOMAIN',
                    'data': indicator,
                    'source': eventData
                })

        elif eventName in ['IP_ADDRESS', 'AFFILIATE_IPADDR'] and self.opts['check_ips']:
            indicators = self.checkIPAddress(eventData)
            for indicator in indicators:
                findings.append({
                    'type': 'HIGH_RISK_IPADDR',
                    'data': indicator,
                    'source': eventData
                })

        elif eventName in ['LEAK_SITE', 'BREACH_DATA', 'DARKNET_MENTION']:
            # Analyze content for corruption/TOC indicators
            content_findings = self.analyzeContent(eventData, eventName)
            findings.extend(content_findings)

        # Generate SpiderFoot events for findings
        for finding in findings:
            evt_type = finding.get('type', 'TOC_INDICATOR')
            evt_data = finding.get('data', '')

            # Use class name for module identification
            module_name = self.__class__.__name__

            # Only create event if SpiderFootEvent is available
            if 'SpiderFootEvent' in globals():
                evt = SpiderFootEvent(evt_type, evt_data, module_name, event)
                if hasattr(self, 'notifyListeners'):
                    self.notifyListeners(evt)

# End of sfp_toc_corruption class
