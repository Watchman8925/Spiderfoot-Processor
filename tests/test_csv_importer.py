#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         test_csv_importer
# Purpose:      Unit tests for CSV importer
#
# Author:       Watchman8925
#
# Created:      2025
# License:      MIT
# -------------------------------------------------------------------------------

import unittest
import tempfile
import csv
from pathlib import Path
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from processor.csv_importer import SpiderFootCSVImporter, load_spiderfoot_csv


class TestSpiderFootCSVImporter(unittest.TestCase):
    """Test cases for SpiderFoot CSV importer."""

    def setUp(self):
        """Set up test fixtures."""
        self.importer = SpiderFootCSVImporter()

        # Create a temporary CSV file for testing
        self.temp_csv = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv')
        self.test_data = [
            {'Type': 'CORRUPTION_INDICATOR', 'Module': 'sfp_toc_corruption',
             'Source': 'example.com', 'Data': 'Corruption keyword detected: fraud'},
            {'Type': 'TOC_INDICATOR', 'Module': 'sfp_toc_corruption',
             'Source': 'test@example.com', 'Data': 'TOC keyword detected: breach'},
            {'Type': 'HIGH_RISK_DOMAIN', 'Module': 'sfp_toc_corruption',
             'Source': 'bad.xyz', 'Data': 'Suspicious TLD: .xyz'},
        ]

        writer = csv.DictWriter(self.temp_csv, fieldnames=['Type', 'Module', 'Source', 'Data'])
        writer.writeheader()
        writer.writerows(self.test_data)
        self.temp_csv.close()

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_csv.name):
            os.unlink(self.temp_csv.name)

    def test_load_csv(self):
        """Test loading CSV file."""
        result = self.importer.load_csv(self.temp_csv.name)

        self.assertIn('data', result)
        self.assertIn('stats', result)
        self.assertEqual(result['stats']['total_records'], 3)

    def test_load_csv_file_not_found(self):
        """Test loading non-existent CSV file."""
        with self.assertRaises(FileNotFoundError):
            self.importer.load_csv('nonexistent.csv')

    def test_filter_by_type(self):
        """Test filtering by event type."""
        self.importer.load_csv(self.temp_csv.name)
        filtered = self.importer.filter_by_type(['CORRUPTION_INDICATOR'])

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['Type'], 'CORRUPTION_INDICATOR')

    def test_filter_by_module(self):
        """Test filtering by module."""
        self.importer.load_csv(self.temp_csv.name)
        filtered = self.importer.filter_by_module(['sfp_toc_corruption'])

        self.assertEqual(len(filtered), 3)

    def test_filter_corruption_indicators(self):
        """Test filtering corruption indicators."""
        self.importer.load_csv(self.temp_csv.name)
        corruption = self.importer.filter_corruption_indicators()

        self.assertEqual(len(corruption), 1)

    def test_filter_toc_indicators(self):
        """Test filtering TOC indicators."""
        self.importer.load_csv(self.temp_csv.name)
        toc = self.importer.filter_toc_indicators()

        self.assertEqual(len(toc), 1)

    def test_search_data(self):
        """Test searching data."""
        self.importer.load_csv(self.temp_csv.name)
        results = self.importer.search_data('fraud')

        self.assertEqual(len(results), 1)

    def test_search_data_specific_field(self):
        """Test searching specific field."""
        self.importer.load_csv(self.temp_csv.name)
        results = self.importer.search_data('breach', field='Data')

        self.assertEqual(len(results), 1)

    def test_get_summary(self):
        """Test getting summary statistics."""
        self.importer.load_csv(self.temp_csv.name)
        summary = self.importer.get_summary()

        self.assertEqual(summary['total_records'], 3)
        self.assertEqual(summary['corruption_indicators'], 1)
        self.assertEqual(summary['toc_indicators'], 1)

    def test_export_filtered(self):
        """Test exporting filtered data."""
        self.importer.load_csv(self.temp_csv.name)
        filtered = self.importer.filter_by_type(['CORRUPTION_INDICATOR'])

        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv')
        output_file.close()

        try:
            self.importer.export_filtered(filtered, output_file.name)
            self.assertTrue(os.path.exists(output_file.name))

            # Verify exported data
            with open(output_file.name, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(len(rows), 1)
        finally:
            if os.path.exists(output_file.name):
                os.unlink(output_file.name)

    def test_convenience_function(self):
        """Test convenience function."""
        result = load_spiderfoot_csv(self.temp_csv.name)

        self.assertIn('data', result)
        self.assertEqual(result['stats']['total_records'], 3)


if __name__ == '__main__':
    unittest.main()
