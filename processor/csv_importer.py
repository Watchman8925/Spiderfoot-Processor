#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         csv_importer
# Purpose:      Import and process SpiderFoot CSV exports
#
# Author:       Watchman8925
#
# Created:      2025
# License:      MIT
# -------------------------------------------------------------------------------

import csv
from pathlib import Path
from typing import Dict, List, Optional, Any


class SpiderFootCSVImporter:
    """Import and process SpiderFoot CSV export files."""

    def __init__(self):
        """Initialize the CSV importer."""
        self.data = []
        self.metadata = {}
        self.stats = {
            'total_records': 0,
            'event_types': {},
            'modules': set(),
            'corruption_indicators': 0,
            'toc_indicators': 0
        }

    def load_csv(self, filepath: str, encoding: str = 'utf-8') -> Dict[str, Any]:
        """
        Load SpiderFoot CSV export file.

        Args:
            filepath: Path to the CSV file
            encoding: File encoding (default: utf-8)

        Returns:
            Dictionary with loaded data and statistics
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"CSV file not found: {filepath}")

        self.data = []
        self.stats = {
            'total_records': 0,
            'event_types': {},
            'modules': set(),
            'corruption_indicators': 0,
            'toc_indicators': 0
        }

        with open(filepath, 'r', encoding=encoding, errors='replace') as f:
            reader = csv.DictReader(f)

            # Store the fieldnames for later use
            self.metadata['fieldnames'] = reader.fieldnames

            for row in reader:
                self.data.append(row)
                self.stats['total_records'] += 1

                # Track event types
                event_type = row.get('Type', 'UNKNOWN')
                self.stats['event_types'][event_type] = \
                    self.stats['event_types'].get(event_type, 0) + 1

                # Track modules
                module = row.get('Module', 'UNKNOWN')
                self.stats['modules'].add(module)

                # Count corruption and TOC indicators
                if event_type == 'CORRUPTION_INDICATOR':
                    self.stats['corruption_indicators'] += 1
                elif event_type == 'TOC_INDICATOR':
                    self.stats['toc_indicators'] += 1

        self.stats['modules'] = list(self.stats['modules'])

        return {
            'data': self.data,
            'stats': self.stats,
            'metadata': self.metadata
        }

    def filter_by_type(self, event_types: List[str]) -> List[Dict]:
        """
        Filter data by event type(s).

        Args:
            event_types: List of event types to filter

        Returns:
            Filtered list of records
        """
        return [row for row in self.data if row.get('Type') in event_types]

    def filter_by_module(self, modules: List[str]) -> List[Dict]:
        """
        Filter data by module(s).

        Args:
            modules: List of module names to filter

        Returns:
            Filtered list of records
        """
        return [row for row in self.data if row.get('Module') in modules]

    def filter_corruption_indicators(self) -> List[Dict]:
        """Get all corruption indicator records."""
        return self.filter_by_type(['CORRUPTION_INDICATOR'])

    def filter_toc_indicators(self) -> List[Dict]:
        """Get all TOC indicator records."""
        return self.filter_by_type(['TOC_INDICATOR'])

    def search_data(self, keyword: str, field: Optional[str] = None) -> List[Dict]:
        """
        Search for keyword in data.

        Args:
            keyword: Keyword to search for
            field: Specific field to search in (optional, searches all if None)

        Returns:
            List of matching records
        """
        keyword_lower = keyword.lower()
        results = []

        for row in self.data:
            if field:
                # Search in specific field
                if field in row and keyword_lower in str(row[field]).lower():
                    results.append(row)
            else:
                # Search in all fields
                for value in row.values():
                    if keyword_lower in str(value).lower():
                        results.append(row)
                        break

        return results

    def export_filtered(self, filtered_data: List[Dict], output_path: str) -> None:
        """
        Export filtered data to a new CSV file.

        Args:
            filtered_data: Filtered data to export
            output_path: Path for the output CSV file
        """
        if not filtered_data:
            raise ValueError("No data to export")

        output_path = Path(output_path)
        fieldnames = self.metadata.get('fieldnames', filtered_data[0].keys())

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_data)

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of loaded data.

        Returns:
            Dictionary with summary statistics
        """
        return {
            'total_records': self.stats['total_records'],
            'event_types_count': len(self.stats['event_types']),
            'modules_count': len(self.stats['modules']),
            'corruption_indicators': self.stats['corruption_indicators'],
            'toc_indicators': self.stats['toc_indicators'],
            'event_types': self.stats['event_types'],
            'modules': self.stats['modules']
        }

    def get_data(self) -> List[Dict]:
        """Get all loaded data."""
        return self.data


def load_spiderfoot_csv(filepath: str) -> Dict[str, Any]:
    """
    Convenience function to load a SpiderFoot CSV file.

    Args:
        filepath: Path to the CSV file

    Returns:
        Dictionary with loaded data and statistics
    """
    importer = SpiderFootCSVImporter()
    return importer.load_csv(filepath)
